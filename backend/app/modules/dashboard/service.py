"""
Service d'agrégation consolidé pour le Tableau de Bord Global AIOps (Bloc 6).

Responsabilités :
  - Agréger les données multi-modules (Parc, Supervision, Cybersécurité, NetDevOps, Audit).
  - Calculer les indicateurs clés de performance (KPIs) en temps réel.
  - Construire la série temporelle réelle (historique SQLite + projection régression linéaire).
  - Fournir les alertes récentes avec corrélation d'incidents.
  - Calculer la répartition de l'état de santé du parc.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from sqlalchemy.orm import Session

from backend.app.db.models import (
    Alerte,
    AuditReseau,
    Equipement,
    EvenementSecurite,
    JournalAudit,
    Metrique,
    Prediction,
)
from backend.app.modules.netdevops.service import _SIMULATED_CONFIGS, _audit_config
from backend.app.modules.supervision.hardware_collector import HardwareCollector


class DashboardService:
    @staticmethod
    def _build_real_telemetry_series(db: Session, equipements: list[Equipement]) -> list[dict[str, Any]]:
        """
        Rôle : Construit la courbe temporelle réelle (historique + prédiction linéaire)
        pour le graphique principal du Dashboard à partir des vraies mesures SQLite.
        Entrées : db (Session), equipements (liste des équipements actifs).
        Sorties : Liste de points {time, actual, predicted, threshold}.
        """
        # Sélectionner en priorité la machine hôte réelle ou l'équipement ayant le plus de mesures
        target_eq: Equipement | None = None
        for eq in equipements:
            if eq.ip == "127.0.0.1" or "Hôte" in (eq.type or ""):
                target_eq = eq
                break
        if not target_eq and equipements:
            target_eq = equipements[0]

        if not target_eq:
            return []

        # Récupérer les 7 dernières mesures réelles (CPU, RAM, Disque) de l'équipement cible
        cpu_rows = (
            db.query(Metrique)
            .filter(Metrique.equipement_id == target_eq.id, Metrique.type_metrique == "cpu_percent")
            .order_by(Metrique.horodatage.desc())
            .limit(7)
            .all()
        )[::-1]
        ram_rows = (
            db.query(Metrique)
            .filter(Metrique.equipement_id == target_eq.id, Metrique.type_metrique == "ram_percent")
            .order_by(Metrique.horodatage.desc())
            .limit(7)
            .all()
        )[::-1]
        disk_rows = (
            db.query(Metrique)
            .filter(Metrique.equipement_id == target_eq.id, Metrique.type_metrique == "disk_percent")
            .order_by(Metrique.horodatage.desc())
            .limit(7)
            .all()
        )[::-1]

        # Récupérer les pentes horaires prédictives calculées par régression linéaire
        preds = {
            p.metrique: p
            for p in db.query(Prediction).filter(Prediction.equipement_id == target_eq.id).all()
        }

        series: list[dict[str, Any]] = []
        count = max(len(cpu_rows), len(ram_rows), len(disk_rows))
        if count == 0:
            return []

        for idx in range(count):
            cpu_val = round(cpu_rows[idx].valeur, 1) if idx < len(cpu_rows) else (round(cpu_rows[-1].valeur, 1) if cpu_rows else 0.0)
            ram_val = round(ram_rows[idx].valeur, 1) if idx < len(ram_rows) else (round(ram_rows[-1].valeur, 1) if ram_rows else 0.0)
            disk_val = round(disk_rows[idx].valeur, 1) if idx < len(disk_rows) else (round(disk_rows[-1].valeur, 1) if disk_rows else 0.0)
            ts_obj = (
                cpu_rows[idx].horodatage
                if idx < len(cpu_rows) and cpu_rows[idx].horodatage
                else datetime.now(timezone.utc)
            )
            label = ts_obj.strftime("%H:%M:%S") if count <= 7 else ts_obj.strftime("%H:%M")
            is_last = idx == count - 1
            series.append(
                {
                    "time": label,
                    "actual": cpu_val,
                    "predicted": cpu_val if is_last else None,
                    "cpu_actual": cpu_val,
                    "cpu_predicted": cpu_val if is_last else None,
                    "ram_actual": ram_val,
                    "ram_predicted": ram_val if is_last else None,
                    "disk_actual": disk_val,
                    "disk_predicted": disk_val if is_last else None,
                    "threshold": 85,
                }
            )

        # Ajouter 4 points de projection future basés sur la régression linéaire réelle
        last_cpu = series[-1]["cpu_actual"]
        last_ram = series[-1]["ram_actual"]
        last_disk = series[-1]["disk_actual"]
        cpu_slope = preds["cpu_percent"].pente_horaire if "cpu_percent" in preds else 0.2
        ram_slope = preds["ram_percent"].pente_horaire if "ram_percent" in preds else 0.15
        disk_slope = preds["disk_percent"].pente_horaire if "disk_percent" in preds else 0.1

        for step_hours in (1, 2, 4, 6):
            proj_cpu = round(min(100.0, max(0.0, last_cpu + cpu_slope * step_hours)), 1)
            proj_ram = round(min(100.0, max(0.0, last_ram + ram_slope * step_hours)), 1)
            proj_disk = round(min(100.0, max(0.0, last_disk + disk_slope * step_hours)), 1)
            series.append(
                {
                    "time": f"+{step_hours}h (Préd.)",
                    "actual": None,
                    "predicted": proj_cpu,
                    "cpu_actual": None,
                    "cpu_predicted": proj_cpu,
                    "ram_actual": None,
                    "ram_predicted": proj_ram,
                    "disk_actual": None,
                    "disk_predicted": proj_disk,
                    "threshold": 85,
                }
            )

        return series

    @staticmethod
    def get_summary(db: Session) -> dict[str, Any]:
        """
        Rôle : Retourne la vue consolidée temps réel de tout le système Sentinelle AIOps.
        Entrées : db (Session SQLAlchemy).
        Sorties : Dictionnaire structuré avec KPIs, répartition santé, alertes, prédictions, télémétrie.
        """
        # S'assurer que la machine hôte réelle a bien été enregistrée et sondée
        try:
            host_eq = HardwareCollector.get_or_create_host_equipment(db)
            has_host_metrics = (
                db.query(Metrique).filter(Metrique.equipement_id == host_eq.id).first() is not None
            )
            if not has_host_metrics:
                HardwareCollector.collect_live_metrics(db)
        except Exception:
            pass

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
            .limit(8)
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
        imminent_failures = [
            p for p in predictions
            if p.ttf_estime_heures is not None and 0 < p.ttf_estime_heures < 168.0
        ]
        ttf_imminents_count = len(imminent_failures)

        predictions_critiques = [
            {
                "id": p.id,
                "equipement_id": p.equipement_id,
                "equipement_nom": p.equipement.nom if p.equipement else f"Équipement #{p.equipement_id}",
                "metrique": p.metrique,
                "valeur_actuelle": round(p.valeur_actuelle, 1),
                "pente_horaire": round(p.pente_horaire, 3),
                "ttf_estime_heures": round(p.ttf_estime_heures, 1) if p.ttf_estime_heures is not None else None,
                "indice_confiance": p.indice_confiance,
                "r2_score": round(p.r2_score, 2),
            }
            for p in sorted(
                predictions,
                key=lambda x: x.ttf_estime_heures if (x.ttf_estime_heures is not None and x.ttf_estime_heures > 0) else 99999,
            )[:6]
        ]

        # 4. Cybersécurité & Détection Anomalies
        anomalies_count = db.query(EvenementSecurite).filter(EvenementSecurite.is_anomaly == True).count()
        total_events = db.query(EvenementSecurite).count()

        # 5. NetDevOps - Score moyen de conformité CIS (audits SQLite + équipements CIS)
        cis_scores: list[float] = []
        persisted_audits = db.query(AuditReseau).order_by(AuditReseau.date_audit.desc()).all()
        audits_by_eq: dict[int, list[AuditReseau]] = {}
        for aud in persisted_audits:
            audits_by_eq.setdefault(aud.equipement_id, []).append(aud)
        for eq_audits in audits_by_eq.values():
            passed = sum(1 for a in eq_audits if a.statut in ("Conforme", "Corrigé"))
            cis_scores.append(round((passed / len(eq_audits)) * 100.0, 1))

        for dev_id, cfg in _SIMULATED_CONFIGS.items():
            rep = _audit_config(dev_id, cfg)
            cis_scores.append(rep["score"])
        cis_moyenne = round(sum(cis_scores) / len(cis_scores), 1) if cis_scores else 0.0

        # 6. Activités récentes d'audit
        recent_audits_records = (
            db.query(JournalAudit)
            .order_by(JournalAudit.horodatage.desc())
            .limit(6)
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
        penalite_alertes = min(30.0, (alertes_critiques_count * 10.0 + (alertes_actives_count - alertes_critiques_count) * 2.0))
        stabilite_ttf = max(0.0, 100.0 - (ttf_imminents_count * 25.0))
        indice_resilience = round(
            (0.40 * sante_moyenne) +
            (0.25 * cis_moyenne) +
            (0.20 * max(0.0, 100.0 - penalite_alertes)) +
            (0.15 * stabilite_ttf),
            1
        )

        telemetry_series = DashboardService._build_real_telemetry_series(db, equipements)

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
            "telemetry_series": telemetry_series,
            "statut_modules": [
                {"nom": "Supervision Prédictive", "statut": "Opérationnel", "metric": "R² Linear Regression", "actif": True},
                {"nom": "Gestion de Parc & Sondes", "statut": "Opérationnel", "metric": f"{total_equipements} nœuds ({equipements_en_ligne} en ligne)", "actif": True},
                {"nom": "Cybersécurité AIOps", "statut": "Opérationnel", "metric": "Isolation Forest RGPD", "actif": True},
                {"nom": "NetDevOps CIS Benchmark", "statut": "Opérationnel", "metric": f"{cis_moyenne}% conformité", "actif": True},
            ],
        }
