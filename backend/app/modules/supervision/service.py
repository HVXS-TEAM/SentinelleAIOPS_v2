"""Service de supervision et calcul prédictif de panne (Time-To-Failure - TTF).

Implémente la régression linéaire prédictive, le calcul de l'erreur MAPE,
l'évaluation de l'indice de confiance et la génération d'alertes préventives.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.db.models import Equipement, Metrique, Prediction, Alerte
from backend.app.core.config import settings
from backend.app.core.audit import log_audit_action


def calculate_mape(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """Calcule le Mean Absolute Percentage Error (MAPE)."""
    mask = y_true != 0
    if not np.any(mask):
        return 0.0
    return float(np.mean(np.abs((y_true[mask] - y_pred[mask]) / y_true[mask])) * 100.0)


def evaluate_confidence(data_points_count: int, r2_score: float) -> str:
    """Évalue l'indice de confiance de la régression."""
    if data_points_count < 6 or r2_score < 0.6:
        return "Faible"
    elif data_points_count < 15 or r2_score < 0.85:
        return "Moyenne"
    return "Haute"


class SupervisionService:
    @staticmethod
    def record_metric(
        db: Session,
        equipement_id: int,
        type_metrique: str,
        valeur: float,
        horodatage: Optional[datetime] = None,
    ) -> Metrique:
        """Enregistre une nouvelle métrique et actualise le statut de collecte."""
        now = horodatage or datetime.now(timezone.utc)
        metric = Metrique(
            equipement_id=equipement_id,
            type_metrique=type_metrique,
            valeur=valeur,
            horodatage=now,
        )
        db.add(metric)

        # Mettre à jour l'équipement
        equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if equipement:
            equipement.derniere_collecte = now
            equipement.statut_collecte = "OK"

        db.commit()
        db.refresh(metric)
        return metric

    @staticmethod
    def record_collection_failure(
        db: Session,
        equipement_id: int,
        motif: str = "Timeout SNMP/SSH",
    ) -> None:
        """Enregistre un échec de collecte pour un équipement (ex. indisponibilité réseau)."""
        equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if equipement:
            equipement.statut_collecte = "Injoignable"
            # Déclencher une alerte si non déjà présente
            existing = db.query(Alerte).filter(
                Alerte.equipement_id == equipement_id,
                Alerte.module_origine == "Supervision",
                Alerte.statut == "Active",
                Alerte.titre.like("%Échec de collecte%"),
            ).first()
            if not existing:
                alerte = Alerte(
                    equipement_id=equipement_id,
                    module_origine="Supervision",
                    severite="WARNING",
                    titre=f"Échec de collecte sur {equipement.nom}",
                    message=f"L'équipement n'a pas répondu aux sondes ({motif}). Statut basculé en Injoignable.",
                    statut="Active",
                )
                db.add(alerte)
            db.commit()

    @staticmethod
    def calculate_ttf(
        db: Session,
        equipement_id: int,
        metrique_cible: str = "disk_percent",
    ) -> Optional[Prediction]:
        """Calcule la tendance, le score R2, l'erreur MAPE et le Time-To-Failure (TTF)."""
        equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if not equipement:
            return None

        # Récupérer l'historique récent (jusqu'à 48 points)
        metrics = (
            db.query(Metrique)
            .filter(
                Metrique.equipement_id == equipement_id,
                Metrique.type_metrique == metrique_cible,
            )
            .order_by(Metrique.horodatage.asc())
            .all()
        )

        if len(metrics) < 3:
            return None

        # Préparer les données en heures relatives depuis le premier point
        t0 = metrics[0].horodatage
        x_hours = np.array([(m.horodatage - t0).total_seconds() / 3600.0 for m in metrics])
        y_values = np.array([m.valeur for m in metrics])
        current_value = float(y_values[-1])

        # Ajustement linéaire (y = pente * x + intercept)
        poly_coeff = np.polyfit(x_hours, y_values, deg=1)
        pente_horaire = float(poly_coeff[0])
        intercept = float(poly_coeff[1])

        # Calcul R²
        y_pred = pente_horaire * x_hours + intercept
        ss_res = np.sum((y_values - y_pred) ** 2)
        ss_tot = np.sum((y_values - np.mean(y_values)) ** 2)
        r2 = float(1.0 - (ss_res / ss_tot)) if ss_tot != 0 else 1.0
        r2 = max(0.0, min(1.0, r2))

        # Calcul MAPE sur le dernier quart de l'échantillon
        split_idx = max(2, int(len(y_values) * 0.75))
        mape = calculate_mape(y_values[split_idx:], y_pred[split_idx:])

        # Évaluation de la confiance
        confiance = evaluate_confidence(len(metrics), r2)

        # Calcul du TTF jusqu'au seuil d'alerte (ou jusqu'à rupture totale 100%)
        seuil = equipement.seuil_disque_alerte or settings.DEFAULT_CRITICAL_DISK_THRESHOLD
        ttf_heures: Optional[float] = None
        date_saturation: Optional[datetime] = None

        if pente_horaire > 0.001:
            if current_value < seuil:
                heures_jusqu_a_seuil = (seuil - current_value) / pente_horaire
                ttf_heures = round(float(heures_jusqu_a_seuil), 2)
            elif current_value < 100.0:
                # Seuil d'alerte déjà dépassé -> TTF jusqu'à rupture totale (100%)
                heures_jusqu_a_panne = (100.0 - current_value) / pente_horaire
                ttf_heures = round(float(heures_jusqu_a_panne), 2)
            else:
                ttf_heures = 0.0

            if ttf_heures is not None and ttf_heures > 0:
                date_saturation = datetime.now(timezone.utc) + timedelta(hours=ttf_heures)

        # Mise à jour ou création de la prédiction en base
        now = datetime.now(timezone.utc)
        prediction = (
            db.query(Prediction)
            .filter(
                Prediction.equipement_id == equipement_id,
                Prediction.metrique == metrique_cible,
            )
            .first()
        )

        if not prediction:
            prediction = Prediction(
                equipement_id=equipement_id,
                metrique=metrique_cible,
                valeur_actuelle=current_value,
                pente_horaire=round(pente_horaire, 3),
                r2_score=round(r2, 3),
                mape_erreur=round(mape, 2),
                indice_confiance=confiance,
                ttf_estime_heures=ttf_heures,
                date_saturation_estimee=date_saturation,
                date_calcul=now,
            )
            db.add(prediction)
        else:
            prediction.valeur_actuelle = current_value
            prediction.pente_horaire = round(pente_horaire, 3)
            prediction.r2_score = round(r2, 3)
            prediction.mape_erreur = round(mape, 2)
            prediction.indice_confiance = confiance
            prediction.ttf_estime_heures = ttf_heures
            prediction.date_saturation_estimee = date_saturation
            prediction.date_calcul = now

        # Génération d'alerte préventive si TTF critique (< 48h)
        if ttf_heures is not None and ttf_heures < settings.DEFAULT_TTF_ALERT_HOURS:
            severite = "CRITICAL" if ttf_heures < 12.0 else "WARNING"
            existing_alert = (
                db.query(Alerte)
                .filter(
                    Alerte.equipement_id == equipement_id,
                    Alerte.module_origine == "Supervision",
                    Alerte.statut == "Active",
                )
                .first()
            )
            titre_alerte = f"Risque de saturation disque sur {equipement.nom}"
            msg_alerte = (
                f"{equipement.nom} : Occupation disque actuelle {current_value:.1f}%. "
                f"Saturation estimée à {seuil}% dans {ttf_heures:.1f}h (R²={r2:.2f}, MAPE={mape:.1f}%)."
            )
            if not existing_alert:
                db.add(
                    Alerte(
                        equipement_id=equipement_id,
                        module_origine="Supervision",
                        severite=severite,
                        titre=titre_alerte,
                        message=msg_alerte,
                        statut="Active",
                        date_creation=now,
                    )
                )
            else:
                existing_alert.severite = severite
                existing_alert.message = msg_alerte

        db.commit()
        db.refresh(prediction)
        return prediction

    @staticmethod
    def simulate_disk_stress(
        db: Session,
        equipement_id: int,
        target_disk_percent: float = 88.5,
        slope_boost: float = 2.5,
    ) -> Prediction:
        """Injecte une saturation accélérée sur un serveur pour valider la démonstration en live."""
        equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if not equipement:
            raise ValueError("Équipement introuvable")

        now = datetime.now(timezone.utc)
        # Injection de 5 nouveaux points de remplissage rapide
        base_val = target_disk_percent - (slope_boost * 4)
        for i in range(5):
            t = now - timedelta(minutes=(4 - i) * 15)
            val = round(base_val + (i * slope_boost), 1)
            db.add(Metrique(equipement_id=equipement_id, type_metrique="disk_percent", valeur=val, horodatage=t))

        db.commit()

        # Recalcul immédiat du TTF
        pred = SupervisionService.calculate_ttf(db, equipement_id, metrique_cible="disk_percent")
        log_audit_action(
            db=db,
            action="SIMULATION_DISK_STRESS",
            cible=equipement.nom,
            details=f"Stress disque simulé à {target_disk_percent}%. Nouveau TTF estimé: {pred.ttf_estime_heures if pred else 'N/A'}h",
        )
        return pred
