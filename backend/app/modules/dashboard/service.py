"""
Service d'agrégation consolidé pour le Tableau de Bord Global AIOps (Bloc 6).

Responsabilités :
  - Agréger les données multi-modules (Parc, Supervision, Cybersécurité, NetDevOps, Audit).
  - Calculer les indicateurs clés de performance (KPIs) en temps réel.
  - Fournir les alertes récentes avec corrélation d'incidents.
  - Calculer la répartition de l'état de santé du parc.
"""

from __future__ import annotations

from typing import Any
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.db.models import (
    Equipement,
    Prediction,
    EvenementSecurite,
    Alerte,
    JournalAudit,
)
from backend.app.modules.netdevops.service import get_available_devices, _audit_config, _SIMULATED_CONFIGS


class DashboardService:
    @staticmethod
    def get_summary(db: Session) -> dict[str, Any]:
        """Retourne la vue consolidée de tout le système Sentinelle AIOps."""
        # 1. Parc & Santé
        equipements = db.query(Equipement).all()
        total_equipements = len(equipements)
        equipements_en_ligne = sum(1 for e in equipements if e.statut_collecte == "OK")
        
        scores = [e.score_sante for e in equipements] if equipements else [100.0]
        sante_moyenne = round(sum(scores) / len(scores), 1) if scores else 100.0

        sain_count = sum(1 for s in scores if s >= 80.0)
        degrade_count = sum(1 for s in scores if 50.0 <= s < 80.0)
        critique_count = sum(1 for s in scores if s < 50.0)

        # 2. Alertes actives & critiques
        alertes_actives_query = db.query(Alerte).filter(Alerte.statut == "Active")
        alertes_actives_count = alertes_actives_query.count()
        alertes_critiques_count = alertes_actives_query.filter(Alerte.severite == "CRITICAL").count()

        recent_alertes_records = (
            db.query(Alerte)
            .order_by(Alerte.date_creation.desc())
            .limit(6)
            .all()
        )
        recent_alertes = [
            {
                "id": a.id,
                "module_origine": a.module_origine,
                "severite": a.severite,
                "titre": a.titre,
                "message": a.message,
                "statut": a.statut,
                "date_creation": a.date_creation.isoformat() if a.date_creation else "",
                "equipement_nom": a.equipement.nom if a.equipement else "Système",
            }
            for a in recent_alertes_records
        ]

        # 3. Supervision Prédictive & Time-To-Failure
        predictions = db.query(Prediction).all()
        # Équipements dont le TTF estimé est sous les 7 jours (168h)
        imminent_failures = [
            p for p in predictions
            if p.ttf_estime_heures is not None and 0 < p.ttf_estime_heures < 168.0
        ]
        ttf_imminents_count = len(imminent_failures)

        predictions_critiques = [
            {
                "id": p.id,
                "equipement_nom": p.equipement.nom if p.equipement else f"Équipement #{p.equipement_id}",
                "metrique": p.metrique,
                "valeur_actuelle": round(p.valeur_actuelle, 1),
                "pente_horaire": round(p.pente_horaire, 3),
                "ttf_estime_heures": round(p.ttf_estime_heures, 1) if p.ttf_estime_heures else None,
                "indice_confiance": p.indice_confiance,
                "r2_score": round(p.r2_score, 2),
            }
            for p in sorted(predictions, key=lambda x: x.ttf_estime_heures if x.ttf_estime_heures is not None else 99999)[:4]
        ]

        # 4. Cybersécurité & Détection Anomalies
        anomalies_count = db.query(EvenementSecurite).filter(EvenementSecurite.is_anomaly == True).count()
        total_events = db.query(EvenementSecurite).count()

        # 5. NetDevOps - Score moyen de conformité CIS sur les configs analysées
        cis_scores: list[float] = []
        for dev_id, cfg in _SIMULATED_CONFIGS.items():
            rep = _audit_config(dev_id, cfg)
            cis_scores.append(rep["score"])
        cis_moyenne = round(sum(cis_scores) / len(cis_scores), 1) if cis_scores else 0.0

        # 6. Activités récentes d'audit
        recent_audits_records = (
            db.query(JournalAudit)
            .order_by(JournalAudit.horodatage.desc())
            .limit(5)
            .all()
        )
        recent_audits = [
            {
                "id": ja.id,
                "nom_utilisateur": ja.nom_utilisateur,
                "action": ja.action,
                "cible": ja.cible,
                "details": ja.details,
                "horodatage": ja.horodatage.isoformat() if ja.horodatage else "",
            }
            for ja in recent_audits_records
        ]

        # Score global de résilience opérationnelle composite (0 à 100)
        # 40% santé parc + 25% conformité CIS + 20% pénalité alertes + 15% stabilité prédictive
        penalite_alertes = min(30.0, (alertes_critiques_count * 10.0 + (alertes_actives_count - alertes_critiques_count) * 2.0))
        stabilite_ttf = max(0.0, 100.0 - (ttf_imminents_count * 25.0))
        indice_resilience = round(
            (0.40 * sante_moyenne) +
            (0.25 * cis_moyenne) +
            (0.20 * max(0.0, 100.0 - penalite_alertes)) +
            (0.15 * stabilite_ttf),
            1
        )

        return {
            "kpis": {
                "indice_resilience": indice_resilience,
                "sante_moyenne": sante_moyenne,
                "total_equipements": total_equipements,
                "equipements_en_ligne": equipements_en_ligne,
                "alertes_actives": alertes_actives_count,
                "alertes_critiques": alertes_critiques_count,
                "anomalies_securite": anomalies_count,
                "total_evenements_securite": total_events,
                "ttf_imminents": ttf_imminents_count,
                "cis_conformite_moyenne": cis_moyenne,
            },
            "repartition_sante": {
                "sain": sain_count,
                "degrade": degrade_count,
                "critique": critique_count,
            },
            "alertes_recentes": recent_alertes,
            "predictions_critiques": predictions_critiques,
            "activites_recentes": recent_audits,
            "statut_modules": [
                {"nom": "Supervision Prédictive", "statut": "Opérationnel", "metric": "R² Linear Regression", "actif": True},
                {"nom": "Gestion de Parc & SNMP", "statut": "Opérationnel", "metric": f"{total_equipements} nœuds", "actif": True},
                {"nom": "Cybersécurité AIOps", "statut": "Opérationnel", "metric": "Isolation Forest RGPD", "actif": True},
                {"nom": "NetDevOps CIS Benchmark", "statut": "Opérationnel", "metric": f"{cis_moyenne}% conformité", "actif": True},
            ],
        }
