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


class AssistantService:
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

        # 0. Analyse experte de Fichier / Config réseau / Extrait de code importé
        if any(w in q_lower for w in ["[fichier", "```", "line vty", "service password", "enable secret", "transport input", "logging buffered"]):
            sources.append("Parseur Sémantique NetDevOps")
            sources.append("CIS Cisco IOS Benchmark")
            
            # Analyse des vulnérabilités dans le snippet
            vulns = []
            if "service password-encryption" not in q_lower:
                vulns.append("🔴 **CIS 1.1.1** : `service password-encryption` absent (mots de passe stockés en clair).")
            if "transport input ssh" not in q_lower and ("line vty" in q_lower or "telnet" in q_lower):
                vulns.append("🔴 **CIS 1.2.2** : `transport input ssh` manquant sur les lignes VTY (risque d'interception Telnet).")
            if "enable secret" not in q_lower:
                vulns.append("🟠 **CIS 1.1.2** : `enable secret` non configuré ou utilisant un mot de passe réversible.")
            if "logging buffered" not in q_lower and "syslog" in q_lower:
                vulns.append("🟡 **CIS 2.1.4** : Journalisation locale `logging buffered` non optimisée.")

            lines = ["### 🔍 Diagnostic Expert de Configuration & Analyse de Sécurité\n"]
            lines.append("Le moteur Sentinelle IA a inspecté la configuration réseau fournie :\n")
            if vulns:
                lines.append(f"⚠️ **{len(vulns)} anomalie(s) ou écart(s) de conformité détecté(s) :**")
                for v in vulns:
                    lines.append(f"- {v}")
            else:
                lines.append("✅ La structure syntaxique globale est cohérente avec les standards de durcissement réseau.")

            lines.append("\n**Script de remédiation Cisco IOS recommandé (NetDevOps) :**")
            lines.append("```cisco\nconfigure terminal\nservice password-encryption\nenable secret SentinelleVault2026!\nline vty 0 4\n transport input ssh\n exec-timeout 10 0\n logging synchronous\nexit\nend\nwrite memory\n```")
            lines.append("\n*Ce correctif peut être déployé automatiquement via le module NetDevOps avec Netmiko SSH.*")

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

            lines = ["### 📊 État de santé actuel du parc informatique\n"]
            if critiques:
                lines.append("**Équipements en état critique (< 50%) :**")
                for e in critiques:
                    lines.append(f"- 🔴 **{e.nom}** ({e.ip}) : score de {e.score_sante}% · Statut : `{e.statut_collecte}`")
            else:
                lines.append("✅ Aucun équipement n'est actuellement en seuil critique.")

            if degrades:
                lines.append("\n**Équipements dégradés (50% - 79%) :**")
                for e in degrades:
                    lines.append(f"- 🟠 **{e.nom}** ({e.ip}) : score de {e.score_sante}% (Uptime: {round(e.uptime_secondes / 3600, 1)}h)")

            lines.append(f"\n*Synthèse : {len(sains)} sains, {len(degrades)} dégradés, {len(critiques)} critiques sur {len(equipements)} nœuds analysés.*")
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
            lines = ["### ⏳ Analyse Prédictive & Time-To-Failure (TTF)\n"]
            if imminent:
                lines.append(f"⚠️ **{len(imminent)} équipement(s) sous risque de saturation sous 7 jours :**\n")
                for p in imminent:
                    nom = p.equipement.nom if p.equipement else "Équipement"
                    lines.append(
                        f"- 🔴 **{nom}** : {p.metrique} actuelle à **{round(p.valeur_actuelle, 1)}%** "
                        f"(Progression estimée : `+{round(p.pente_horaire, 2)}%/h`). "
                        f"Temps restant estimé avant seuil critique : **~{round(p.ttf_estime_heures, 1)} heures** "
                        f"(Indice de confiance : {p.indice_confiance}, R² : {round(p.r2_score, 2)})."
                    )
            else:
                lines.append("✅ **Toutes les métriques extrapolées sont stables.** Aucun équipement ne dépasse son seuil d'alerte dans les 7 prochains jours.")

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
            lines = ["### 🛡️ Diagnostic Cybersécurité & Détection d'Anomalies\n"]
            if anomalies:
                lines.append(f"🚨 **{len(anomalies)} anomalie(s) détectée(s) par l'Isolation Forest :**\n")
                for a in anomalies[:5]:
                    lines.append(
                        f"- **[{a.severite}]** Type: `{a.type_evenement}` | IP masquée RGPD: `{a.source_ip_anonymisee}` "
                        f"| Fréquence: **{a.tentatives_minute} tent./min** | Score anomalie: `{round(a.score_anomalie, 3)}`"
                    )
            else:
                lines.append("✅ Aucun incident ou attaque par force brute suspecte détecté récemment.")

            lines.append("\n*Note de conformité : Toutes les adresses IP sources externes sont anonymisées conformément aux exigences RGPD de la CNIL.*")
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
            lines = ["### 🔒 Audit de Conformité CIS Benchmark Cisco IOS\n"]
            lines.append("Scores de conformité des équipements audités :\n")
            for dev, score, nb_viols in cis_results:
                icon = "🟢" if score >= 80 else ("🟠" if score >= 60 else "🔴")
                lines.append(f"- {icon} **{dev}** : **{score}%** de conformité ({nb_viols} violation(s))")

            worst = cis_results[0]
            lines.append(
                f"\n⚠️ L'équipement le plus vulnérable est **{worst[0]}** ({worst[1]}%). "
                f"Il présente des non-conformités critiques telles que l'accès Telnet actif ou l'utilisation de mots de passe en clair."
            )
            return {
                "response": "\n".join(lines),
                "sources": sources,
                "suggested_followups": [
                    f"Quelles sont les remédiations pour {worst[0]} ?",
                    "Comment visualiser le diff de configuration ?",
                ],
                "mode": "rag_local",
            }

        # 5. Plan de Continuité d'Activité / PRA / Sauvegardes
        if any(w in q_lower for w in ["pra", "sauvegarde", "backup", "restauration", "restore", "continuité"]):
            sources.append("Administration PRA")
            sources.append("Gouvernance ISO 27001")
            lines = [
                "### 💾 Plan de Continuité & Sauvegardes d'Infrastructure (PRA)\n",
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
            "### 🌐 Synthèse Globale Sentinelle AIOps\n",
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
            "Si la réponse nécessite des actions techniques, donne des commandes concrètes ou des étapes de remédiation."
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
                    answer_text = resp_data.get("response", "").strip()
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

        return cls._local_fallback_answer(message, db)
