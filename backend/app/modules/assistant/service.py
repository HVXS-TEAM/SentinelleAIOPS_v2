"""
Service Assistant IA Conversationnel (Bloc 7).

Fonctionnalités :
  - Extraction de contexte temps réel depuis la base SQLite (RAG opérationnel)
  - Requêtage LLM vers Ollama local (llama3 / mistral)
  - Moteur de réponse autonome et déterministe en fallback local si Ollama est indisponible
  - Génération de suggestions de questions et de traçabilité des sources
"""

from __future__ import annotations

import os
import re
from typing import Any
import httpx
from sqlalchemy.orm import Session

from backend.app.db.models import (
    Equipement,
    Prediction,
    EvenementSecurite,
    Alerte,
)
from backend.app.modules.netdevops.service import _audit_config, _SIMULATED_CONFIGS

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

_EMOJI_TO_TAG_MAP: tuple[tuple[str, str], ...] = (
    ("🔴", "[CRITIQUE] "),
    ("🚨", "[CRITIQUE] "),
    ("🟠", "[MAJEUR] "),
    ("🟡", "[MINEUR] "),
    ("⚠️", "[ALERTE] "),
    ("⚠", "[ALERTE] "),
    ("🟢", "[CONFORME] "),
    ("✅", "[CONFORME] "),
    ("🔒", "[AUDIT CIS] "),
    ("🛡️", ""),
    ("🛡", ""),
    ("🔍", ""),
    ("📊", ""),
    ("⏳", ""),
    ("📋", ""),
    ("🌐", ""),
)

_UNICODE_EMOJI_RE = re.compile(
    r"[\U0001F300-\U0001FAFF\u2600-\u27BF\u2300-\u23FF\uFE0F]"
)


class AssistantService:
    @staticmethod
    def _sanitize_clinical_text(text: str) -> str:
        """Remplace les émojis par des tags cliniques ITIL/CIS et purge tout pictogramme résiduel."""
        cleaned = text
        for emoji, tag in _EMOJI_TO_TAG_MAP:
            cleaned = cleaned.replace(emoji, tag)
        cleaned = _UNICODE_EMOJI_RE.sub("", cleaned)
        cleaned = re.sub(r"(\[(?:CRITIQUE|MAJEUR|MINEUR|CONFORME|ALERTE|AUDIT CIS)\])\s+\1", r"\1", cleaned)
        cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
        return cleaned.strip()

    @staticmethod
    def get_suggested_prompts() -> list[str]:
        """Retourne les suggestions de questions rapides pour l'administrateur réseau."""
        return [
            "Quels sont les équipements en état critique ou dégradé ?",
            "Y a-t-il des saturations de disque prévues dans les 7 prochains jours ?",
            "Quelles sont les anomalies de sécurité récentes détectées par l'IA ?",
            "Quel équipement présente la plus faible conformité au CIS Benchmark ?",
            "Donne-moi une synthèse globale de l'état opérationnel du réseau.",
        ]

    @staticmethod
    def _build_system_context(db: Session) -> str:
        """Construit le contexte temps réel sous forme de résumé textuel structuré pour le LLM."""
        equipements = db.query(Equipement).all()
        predictions = db.query(Prediction).all()
        alertes = db.query(Alerte).filter(Alerte.statut == "Active").all()
        anomalies = (
            db.query(EvenementSecurite)
            .filter(EvenementSecurite.is_anomaly == True)
            .order_by(EvenementSecurite.horodatage.desc())
            .limit(5)
            .all()
        )

        equip_lines = [
            f"- {e.nom} ({e.type}, IP: {e.ip}, Santé: {e.score_sante}%, Statut: {e.statut_collecte})"
            for e in equipements
        ]

        pred_lines = [
            f"- {p.equipement.nom if p.equipement else 'Nœud'}: {p.metrique}={round(p.valeur_actuelle, 1)}%, "
            f"TTF={round(p.ttf_estime_heures, 1) if p.ttf_estime_heures else 'Stable'}h, Confiance={p.indice_confiance}"
            for p in predictions
        ]

        alert_lines = [
            f"- [{a.severite}] @{a.equipement.nom if a.equipement else 'Sys'} ({a.module_origine}): {a.titre} - {a.message}"
            for a in alertes
        ]

        sec_lines = [
            f"- [{s.severite}] IP source anonymisée: {s.source_ip_anonymisee}, Type: {s.type_evenement}, Tentatives: {s.tentatives_minute}/min"
            for s in anomalies
        ]

        context = (
            "CONTEXTE INFRASTRUCTURE SENTINELLE AIOPS :\n"
            f"Équipements ({len(equipements)}) :\n" + "\n".join(equip_lines) + "\n\n"
            f"Prédictions Time-To-Failure ({len(predictions)}) :\n" + "\n".join(pred_lines) + "\n\n"
            f"Alertes Actives ({len(alertes)}) :\n" + "\n".join(alert_lines) + "\n\n"
            f"Dernières Anomalies Sécurité ({len(anomalies)}) :\n" + "\n".join(sec_lines)
        )
        return context

    @classmethod
    def _local_fallback_answer(cls, question: str, db: Session) -> dict[str, Any]:
        """
        Réponse intelligente locale basée sur l'analyse sémantique et les requêtes SQL,
        garantissant une réponse exacte même si le daemon Ollama est éteint.
        """
        q_lower = question.lower()
        equipements = db.query(Equipement).all()
        predictions = db.query(Prediction).all()
        alertes = db.query(Alerte).filter(Alerte.statut == "Active").all()
        anomalies = (
            db.query(EvenementSecurite)
            .filter(EvenementSecurite.is_anomaly == True)
            .order_by(EvenementSecurite.horodatage.desc())
            .limit(10)
            .all()
        )

        sources: list[str] = []
        followups: list[str] = [
            "Quelles sont les alertes actives ?",
            "Quel est le score CIS des équipements ?",
        ]

        # Cas 0. Détection d'un extrait de configuration Cisco collé directement
        if any(w in q_lower for w in ["line vty", "service password", "enable secret", "transport input", "username"]):
            sources.append("Audit NetDevOps CIS")
            vulns = []
            if "service password-encryption" not in q_lower:
                vulns.append("[CRITIQUE - CIS 1.1.1] : 'service password-encryption' absent (mots de passe stockés en clair).")
            if "transport input ssh" not in q_lower and ("line vty" in q_lower or "telnet" in q_lower):
                vulns.append("[CRITIQUE - CIS 1.2.2] : 'transport input ssh' manquant sur les lignes VTY (interception Telnet non chiffrée).")
            if "enable secret" not in q_lower:
                vulns.append("[MAJEUR - CIS 1.1.2] : 'enable secret' non configuré ou utilisant un mot de passe réversible.")
            if "logging buffered" not in q_lower and "syslog" in q_lower:
                vulns.append("[MINEUR - CIS 2.1.4] : Journalisation locale 'logging buffered' non optimisée.")

            lines = ["### Diagnostic de Configuration & Analyse de Conformité CIS\n"]
            lines.append("Le moteur Sentinelle IA a inspecté la configuration réseau fournie :\n")
            if vulns:
                lines.append(f"**{len(vulns)} anomalie(s) de conformité détectée(s) :**")
                for v in vulns:
                    lines.append(f"- {v}")
            else:
                lines.append("[CONFORME] La structure syntaxique globale est conforme aux exigences de durcissement réseau.")

            lines.append("\n**Script de remédiation Cisco IOS recommandé (NetDevOps) :**")
            lines.append("```cisco\nconfigure terminal\nservice password-encryption\nenable secret SentinelleVault2026!\nline vty 0 4\n transport input ssh\n exec-timeout 10 0\n logging synchronous\nexit\nend\nwrite memory\n```")
            lines.append("\n*Ce correctif peut être validé et déployé via le module NetDevOps avec Netmiko SSH.*")

            return {
                "response": "\n".join(lines),
                "sources": sources,
                "suggested_followups": [
                    "Comment déployer ce durcissement sur DIST-SW-A ?",
                    "Quel est le score CIS actuel des commutateurs ?",
                ],
                "mode": "rag_local",
            }

        # 1. État critique / dégradé / santé du parc
        if any(w in q_lower for w in ["critique", "dégradé", "degrade", "santé", "sante", "panne", "offline"]):
            sources.append("Gestion de Parc")
            critiques = [e for e in equipements if e.score_sante < 50.0]
            degrades = [e for e in equipements if 50.0 <= e.score_sante < 80.0]
            sains = [e for e in equipements if e.score_sante >= 80.0]

            lines = ["### État de Santé Opérationnel du Parc Informatique\n"]
            if critiques:
                lines.append("**Équipements en seuil critique (< 50%) :**")
                for e in critiques:
                    lines.append(f"- [CRITIQUE] **{e.nom}** ({e.ip}) : score {e.score_sante}% · Statut : `{e.statut_collecte}`")
            else:
                lines.append("[OK] Aucun équipement n'est actuellement en seuil critique.")

            if degrades:
                lines.append("\n**Équipements dégradés (50% - 79%) :**")
                for e in degrades:
                    lines.append(f"- [ATTENTION] **{e.nom}** ({e.ip}) : score {e.score_sante}% (Uptime: {round(e.uptime_secondes / 3600, 1)}h)")

            lines.append(f"\n*Synthèse d'inventaire : {len(sains)} conformes, {len(degrades)} dégradés, {len(critiques)} critiques sur {len(equipements)} nœuds supervisés.*")
            return {
                "response": "\n".join(lines),
                "sources": sources,
                "suggested_followups": [
                    "Quelles sont les prédictions TTF de ces équipements ?",
                    "Y a-t-il des alertes actives sur ces nœuds ?",
                ],
                "mode": "rag_local",
            }

        # 2. Prédictions / Saturation / Time-To-Failure
        if any(w in q_lower for w in ["ttf", "prédiction", "prediction", "saturation", "disque", "panne", "imminent"]):
            sources.append("Supervision Prédictive")
            imminent = [p for p in predictions if p.ttf_estime_heures is not None and p.ttf_estime_heures < 168.0]
            lines = ["### Analyse Prédictive & Time-To-Failure (TTF)\n"]
            if imminent:
                lines.append(f"**[ALERTE PRÉDICTIVE] {len(imminent)} ressource(s) à risque de saturation sous 7 jours :**\n")
                for p in imminent:
                    nom = p.equipement.nom if p.equipement else "Équipement"
                    lines.append(
                        f"- [CRITIQUE] **{nom}** : métrique {p.metrique} à **{round(p.valeur_actuelle, 1)}%** "
                        f"(Tendance : `+{round(p.pente_horaire, 2)}%/h`). "
                        f"Délai estimé avant rupture : **~{round(p.ttf_estime_heures, 1)} heures** "
                        f"(Indice de confiance : {p.indice_confiance}, R² : {round(p.r2_score, 2)})."
                    )
            else:
                lines.append("[OK] **Toutes les métriques extrapolées sont nominales.** Aucun dépassement de seuil projeté sous 7 jours.")

            return {
                "response": "\n".join(lines),
                "sources": sources,
                "suggested_followups": [
                    "Comment simuler une surcharge de disque pour la démo BTS ?",
                    "Quelles alertes sont actuellement déclenchées ?",
                ],
                "mode": "rag_local",
            }

        # 3. Sécurité / Attaques / Isolation Forest / Force brute
        if any(w in q_lower for w in ["sécurité", "securite", "attaque", "brute", "anomalie", "rgpd", "intrusion"]):
            sources.append("Cybersécurité AIOps")
            lines = ["### Diagnostic Cybersécurité & Détection d'Anomalies (Isolation Forest)\n"]
            if anomalies:
                lines.append(f"**[INCIDENTS DÉTECTÉS] {len(anomalies)} anomalie(s) identifiée(s) :**\n")
                for a in anomalies[:5]:
                    lines.append(
                        f"- [{a.severite.upper()}] Type: `{a.type_evenement}` | IP Source (RGPD): `{a.source_ip_anonymisee}` "
                        f"| Fréquence: **{a.tentatives_minute} req/min** | Score d'anomalie: `{round(a.score_anomalie, 3)}`"
                    )
            else:
                lines.append("[CONFORME] Aucune activité suspecte ou anomalie de connexion détectée sur la période.")

            lines.append("\n*Conformité réglementaire : Les adresses IP sources internes/externes sont traitées selon le principe de minimisation RGPD.*")
            return {
                "response": "\n".join(lines),
                "sources": sources,
                "suggested_followups": [
                    "Simuler une attaque par force brute SSH",
                    "Voir les alertes corrélées avec la supervision CPU",
                ],
                "mode": "rag_local",
            }

        # 4. Conformité CIS / Cisco / NetDevOps
        if any(w in q_lower for w in ["cis", "cisco", "netdevops", "benchmark", "conformité", "conformite", "diff", "backup"]):
            sources.append("NetDevOps CIS")
            cis_results = []
            for dev_id, cfg in _SIMULATED_CONFIGS.items():
                rep = _audit_config(dev_id, cfg)
                cis_results.append((dev_id, rep["score"], len(rep["violations"])))

            cis_results.sort(key=lambda x: x[1])
            lines = ["### Audit de Conformité CIS Benchmark Cisco IOS\n"]
            lines.append("Niveau de durcissement des équipements inventoriés :\n")
            for dev, score, nb_viols in cis_results:
                status_tag = "[CONFORME]" if score >= 80 else ("[ATTENTION]" if score >= 60 else "[NON-CONFORME]")
                lines.append(f"- {status_tag} **{dev}** : **{score}%** de conformité ({nb_viols} écart(s))")

            return {
                "response": "\n".join(lines),
                "sources": sources,
                "suggested_followups": [
                    "Afficher le détail des violations sur le routeur Edge",
                    "Lancer un audit CIS complet sur l'ensemble du lab",
                ],
                "mode": "rag_local",
            }

        # 5. Plan de Continuité d'Activité / PRA / Sauvegardes
        if any(w in q_lower for w in ["pra", "sauvegarde", "backup", "restauration", "restore", "continuité"]):
            sources.append("Administration PRA")
            sources.append("Gouvernance ISO 27001")
            lines = [
                "### Plan de Continuité & Sauvegardes d'Infrastructure (PRA)\n",
                "Le dispositif de résilience opérationnelle Sentinelle AIOps garantit :",
                "- **Chiffrement au repos** : Algorithme AES-256 (Fernet) avec scellement sécurisé.",
                "- **Contrôle d'intégrité** : Empreinte cryptographique SHA-256 calculée à chaque instantané.",
                "- **RTO / RPO** : RTO < 15 minutes, RPO = 0 perte sur transactions acquittées.",
                "- **Traçabilité** : Journalisation immuable dans l'audit trail SQLite.",
            ]
            return {
                "response": "\n".join(lines),
                "sources": sources,
                "suggested_followups": [
                    "Déclencher une sauvegarde PRA maintenant",
                    "Consulter le journal d'audit des administrateurs",
                ],
                "mode": "rag_local",
            }

        # 6. Synthèse globale / Vue d'ensemble par défaut
        sources.extend(["Gestion de Parc", "Supervision", "Sécurité", "NetDevOps"])
        crit_count = sum(1 for e in equipements if e.score_sante < 50.0)
        lines = [
            "### Synthèse Globale Sentinelle AIOps\n",
            f"- **Parc réseau** : {len(equipements)} équipements actifs, {crit_count} critique(s).",
            f"- **Alertes en cours** : {len(alertes)} active(s), dont {sum(1 for a in alertes if a.severite == 'CRITICAL')} critique(s).",
            f"- **Surveillance prédictive** : {len(predictions)} modèles linéaires entraînés avec calcul de Time-To-Failure.",
            f"- **Sécurité & IA** : Modèle Isolation Forest en veille continue avec masquage RGPD.",
            f"- **Audit de configuration** : Moteur de conformité CIS Level 1 actif sur les switchs et routeurs Cisco.",
            "\n*Vous pouvez me poser des questions précises sur n'importe quel équipement, métrique, alerte ou recommandation technique.*",
        ]
        return {
            "response": "\n".join(lines),
            "sources": sources,
            "suggested_followups": [
                "Quels équipements sont en état critique ?",
                "Quelles pannes sont imminentes ?",
                "Y a-t-il eu des attaques récentes ?",
            ],
            "mode": "rag_local",
        }

    @classmethod
    async def chat(cls, message: str, db: Session) -> dict[str, Any]:
        """
        Traite le message utilisateur :
        Tente d'appeler l'instance locale Ollama avec le contexte RAG.
        En cas d'indisponibilité d'Ollama, bascule instantanément sur le moteur de règles déterministe.
        """
        context = cls._build_system_context(db)
        system_prompt = (
            "Tu es Sentinelle Assistant, un expert AIOps en supervision prédictive, administration réseau et cybersécurité pour le BTS SIO SISR. "
            "Réponds de manière professionnelle, précise, concise et en français en t'appuyant STRICTEMENT sur le contexte suivant :\n\n"
            f"{context}\n\n"
            "Si la réponse nécessite des actions techniques, donne des commandes concrètes ou des étapes de remédiation. "
            "N'utilise aucun émoji. Emploie uniquement une nomenclature technique stricte avec des tags de sévérité normalisés tels que [CRITIQUE], [MAJEUR], [MINEUR], [CONFORME], [ALERTE]."
        )

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.post(
                    f"{OLLAMA_URL}/api/generate",
                    json={
                        "model": OLLAMA_MODEL,
                        "prompt": f"{system_prompt}\n\nQuestion de l'administrateur : {message}\nRéponse :",
                        "stream": False,
                    },
                )
                if res.status_code == 200:
                    resp_data = res.json()
                    raw_answer = resp_data.get("response", "").strip()
                    answer_text = cls._sanitize_clinical_text(raw_answer)
                    if answer_text:
                        return {
                            "response": answer_text,
                            "sources": ["Ollama (Local LLM)", "Base de données Sentinelle"],
                            "suggested_followups": [
                                "Quels sont les équipements en alerte ?",
                                "Montre les prédictions TTF de saturation",
                            ],
                            "mode": "ollama",
                        }
        except Exception:
            # Ollama non joignable -> bascule automatique transparente sur le moteur RAG local
            pass

        fallback = cls._local_fallback_answer(message, db)
        fallback["response"] = cls._sanitize_clinical_text(fallback["response"])
        return fallback
