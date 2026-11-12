"""Service de supervision et calcul prédictif de panne (Time-To-Failure - TTF).

Implémente la régression linéaire prédictive, le calcul de l'erreur MAPE,
l'évaluation de l'indice de confiance, la gestion complète du cycle de vie des alertes
et la rétention de la base de séries temporelles SQLite.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
import numpy as np
from sqlalchemy.orm import Session

from backend.app.db.models import Equipement, Metrique, Prediction, Alerte, User
from backend.app.core.config import settings
from backend.app.core.audit import log_audit_action


def calculate_mape(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """
    Rôle : Calcule le Mean Absolute Percentage Error (MAPE) entre les mesures réelles et la droite de régression.
    Entrées : Tableaux numpy y_true (valeurs mesurées) et y_pred (valeurs prédites).
    Sorties : Pourcentage d'erreur moyen flottant.
    Cas d'erreur : Ignore les valeurs nulles dans y_true pour éviter toute division par zéro.
    """
    mask = y_true != 0
    if not np.any(mask):
        return 0.0
    return float(np.mean(np.abs((y_true[mask] - y_pred[mask]) / y_true[mask])) * 100.0)


def evaluate_confidence(data_points_count: int, r2_score: float) -> str:
    """
    Rôle : Évalue l'indice de confiance qualitatif du modèle de régression linéaire.
    Entrées : Nombre de points d'historique (data_points_count) et coefficient R² (r2_score).
    Sorties : Niveau de confiance ('Faible', 'Moyenne' ou 'Haute').
    Cas d'erreur : Retourne 'Faible' si l'échantillon comporte moins de 6 points.
    """
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
        """
        Rôle : Enregistre une nouvelle métrique, actualise le statut de collecte et résout automatiquement
               les éventuelles alertes d'indisponibilité précédentes.
        Entrées : Session DB, ID de l'équipement, type de métrique, valeur mesurée, horodatage optionnel.
        Sorties : Objet Metrique persisté.
        Cas d'erreur : Gère l'absence éventuelle de l'équipement sans interrompre l'insertion.
        """
        now = horodatage or datetime.now(timezone.utc)
        metric = Metrique(
            equipement_id=equipement_id,
            type_metrique=type_metrique,
            valeur=valeur,
            horodatage=now,
        )
        db.add(metric)

        # Mettre à jour l'équipement et résoudre les alertes de perte de sonde si l'équipement répond à nouveau
        equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if equipement:
            was_unreachable = equipement.statut_collecte == "Injoignable"
            equipement.derniere_collecte = now
            equipement.statut_collecte = "OK"
            if was_unreachable:
                stale_alerts = (
                    db.query(Alerte)
                    .filter(
                        Alerte.equipement_id == equipement_id,
                        Alerte.module_origine == "Supervision",
                        Alerte.statut == "Active",
                        Alerte.titre.like("%Échec de collecte%"),
                    )
                    .all()
                )
                for st_alert in stale_alerts:
                    st_alert.statut = "Résolue"
                    st_alert.date_acquittement = now
                    st_alert.acquittee_par = "Auto-Recovery"

        db.commit()
        db.refresh(metric)
        return metric

    @staticmethod
    def record_collection_failure(
        db: Session,
        equipement_id: int,
        motif: str = "Timeout ICMP/SSH",
    ) -> None:
        """
        Rôle : Enregistre un échec de collecte pour un équipement et génère une alerte active s'il n'en existe pas.
        Entrées : Session DB, ID de l'équipement, motif technique de l'échec.
        Sorties : Aucune.
        Cas d'erreur : Ne duplique pas l'alerte si une alerte active identique existe déjà.
        """
        equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if equipement:
            equipement.statut_collecte = "Injoignable"
            existing = (
                db.query(Alerte)
                .filter(
                    Alerte.equipement_id == equipement_id,
                    Alerte.module_origine == "Supervision",
                    Alerte.statut == "Active",
                    Alerte.titre.like("%Échec de collecte%"),
                )
                .first()
            )
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
        """
        Rôle : Calcule la tendance horaire, le score R², l'erreur MAPE et le Time-To-Failure (TTF) par régression linéaire.
        Entrées : Session DB, ID de l'équipement, nom de la métrique ('disk_percent', 'ram_percent', 'cpu_percent').
        Sorties : Instance Prediction mise à jour ou créée, ou None si moins de 3 points de mesure.
        Cas d'erreur : Gère les séries temporelles à intervalle court ou constant (pente nulle ou négative).
        """
        equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if not equipement:
            return None

        # Récupérer les 48 derniers points chronologiques
        recent_metrics = (
            db.query(Metrique)
            .filter(
                Metrique.equipement_id == equipement_id,
                Metrique.type_metrique == metrique_cible,
            )
            .order_by(Metrique.horodatage.desc())
            .limit(48)
            .all()
        )
        metrics = list(reversed(recent_metrics))

        if len(metrics) < 3:
            return None

        # Utiliser l'axe séquentiel régulier pour éviter toute distorsion de pente après mise en veille ou redémarrage
        x_hours = np.arange(len(metrics), dtype=float)

        y_values = np.array([m.valeur for m in metrics], dtype=float)
        current_value = float(y_values[-1])

        # Ajustement linéaire (y = pente * x + intercept)
        poly_coeff = np.polyfit(x_hours, y_values, deg=1)
        pente_horaire = float(poly_coeff[0])
        intercept = float(poly_coeff[1])

        # Calcul R²
        y_pred = pente_horaire * x_hours + intercept
        ss_res = float(np.sum((y_values - y_pred) ** 2))
        ss_tot = float(np.sum((y_values - np.mean(y_values)) ** 2))
        r2 = float(1.0 - (ss_res / ss_tot)) if ss_tot > 1e-9 else 1.0
        r2 = max(0.0, min(1.0, r2))

        # Calcul MAPE sur le dernier quart de l'échantillon
        split_idx = max(1, int(len(y_values) * 0.75))
        mape = calculate_mape(y_values[split_idx:], y_pred[split_idx:])

        # Évaluation de la confiance
        confiance = evaluate_confidence(len(metrics), r2)

        # Calcul du TTF jusqu'au seuil d'alerte (ou jusqu'à rupture totale 100%)
        seuil = (
            equipement.seuil_disque_alerte or settings.DEFAULT_CRITICAL_DISK_THRESHOLD
            if metrique_cible == "disk_percent"
            else 90.0
        )
        ttf_heures: Optional[float] = None
        date_saturation: Optional[datetime] = None

        if pente_horaire > 0.001:
            if current_value < seuil:
                heures_jusqu_a_seuil = (seuil - current_value) / pente_horaire
                ttf_heures = round(float(heures_jusqu_a_seuil), 2)
            elif current_value < 100.0:
                heures_jusqu_a_panne = (100.0 - current_value) / pente_horaire
                ttf_heures = round(float(heures_jusqu_a_panne), 2)
            else:
                ttf_heures = 0.0

            if ttf_heures is not None and ttf_heures > 0:
                # Borner l'extrapolation de date à 10 ans max pour éviter OverflowError sur datetime
                capped_hours = min(ttf_heures, 87600.0)
                date_saturation = datetime.now(timezone.utc) + timedelta(hours=capped_hours)

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

        # Génération d'alerte préventive si TTF critique (< 48h) sur le disque
        if metrique_cible == "disk_percent" and ttf_heures is not None and ttf_heures < settings.DEFAULT_TTF_ALERT_HOURS:
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
    def list_alerts(db: Session, statut: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Rôle : Liste les alertes de supervision et multi-modules avec filtrage par statut.
        Entrées : Session DB, statut optionnel ('Active', 'Acquittée', 'Résolue', 'Toutes'), limite.
        Sorties : Liste de dictionnaires représentant les alertes enrichies du nom de l'équipement.
        Cas d'erreur : Retourne une liste vide si aucune alerte ne correspond.
        """
        query = db.query(Alerte)
        if statut and statut != "Toutes":
            query = query.filter(Alerte.statut == statut)
        records = query.order_by(Alerte.date_creation.desc()).limit(limit).all()
        return [
            {
                "id": a.id,
                "equipement_id": a.equipement_id,
                "equipement_nom": a.equipement.nom if a.equipement else "Système",
                "module_origine": a.module_origine,
                "severite": a.severite,
                "titre": a.titre,
                "message": a.message,
                "statut": a.statut,
                "correlation_id": a.correlation_id,
                "date_creation": a.date_creation,
                "date_acquittement": a.date_acquittement,
                "acquittee_par": a.acquittee_par,
            }
            for a in records
        ]

    @staticmethod
    def acknowledge_alert(db: Session, alerte_id: int, user: Optional[User] = None) -> Alerte:
        """
        Rôle : Acquitte une alerte active et journalise l'opération dans l'audit trail.
        Entrées : Session DB, ID de l'alerte, utilisateur authentifié.
        Sorties : Instance Alerte mise à jour.
        Cas d'erreur : Lève ValueError si l'alerte est introuvable.
        """
        alerte = db.query(Alerte).filter(Alerte.id == alerte_id).first()
        if not alerte:
            raise ValueError(f"Alerte #{alerte_id} introuvable")

        now = datetime.now(timezone.utc)
        username = user.identifiant if user else "admin"
        alerte.statut = "Acquittée"
        alerte.date_acquittement = now
        alerte.acquittee_par = username
        db.commit()
        db.refresh(alerte)

        log_audit_action(
            db=db,
            action="ALERT_ACKNOWLEDGE",
            cible=f"Alerte #{alerte.id} ({alerte.titre})",
            user=user,
            details=f"Alerte acquittée par {username}",
        )
        return alerte

    @staticmethod
    def resolve_alert(db: Session, alerte_id: int, user: Optional[User] = None) -> Alerte:
        """
        Rôle : Marque une alerte comme définitivement résolue, recalcule le score de santé de l'équipement associé
               et journalise l'action.
        Entrées : Session DB, ID de l'alerte, utilisateur authentifié.
        Sorties : Instance Alerte résolue.
        Cas d'erreur : Lève ValueError si l'alerte est introuvable.
        """
        alerte = db.query(Alerte).filter(Alerte.id == alerte_id).first()
        if not alerte:
            raise ValueError(f"Alerte #{alerte_id} introuvable")

        now = datetime.now(timezone.utc)
        username = user.identifiant if user else "admin"
        alerte.statut = "Résolue"
        if not alerte.date_acquittement:
            alerte.date_acquittement = now
        alerte.acquittee_par = username
        db.commit()
        db.refresh(alerte)

        if alerte.equipement_id:
            from backend.app.modules.parc.service import ParcService
            ParcService.calculate_health_score(db, alerte.equipement_id)

        log_audit_action(
            db=db,
            action="ALERT_RESOLVE",
            cible=f"Alerte #{alerte.id} ({alerte.titre})",
            user=user,
            details=f"Incident résolu et clôturé par {username}",
        )
        return alerte

    @staticmethod
    def purge_old_metrics(db: Session, retention_days: int = 30) -> int:
        """
        Rôle : Supprime les points de métriques antérieurs à la période de rétention pour maîtriser la taille SQLite.
        Entrées : Session DB, nombre de jours de rétention (défaut 30 jours).
        Sorties : Nombre d'enregistrements purgés.
        Cas d'erreur : Annule la transaction en cas de verrou SQLite temporaire.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        try:
            deleted = db.query(Metrique).filter(Metrique.horodatage < cutoff).delete(synchronize_session=False)
            db.commit()
            return int(deleted or 0)
        except Exception:
            db.rollback()
            return 0

    @staticmethod
    def simulate_disk_stress(
        db: Session,
        equipement_id: int,
        target_disk_percent: float = 88.5,
        slope_boost: float = 2.5,
    ) -> Prediction:
        """
        Rôle : Injecte un test de charge disque accéléré sur un équipement pour éprouver le moteur d'alerte TTF.
        Entrées : Session DB, ID équipement, pourcentage disque cible, accélération horaire.
        Sorties : Instance Prediction recalculée.
        Cas d'erreur : Lève ValueError si l'équipement cible n'existe pas.
        """
        equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if not equipement:
            raise ValueError("Équipement introuvable")

        now = datetime.now(timezone.utc)
        # Purger les anciens points de stress disque pour construire une rampe monotone réaliste sans dents de scie
        db.query(Metrique).filter(
            Metrique.equipement_id == equipement_id,
            Metrique.type_metrique == "disk_percent",
        ).delete(synchronize_session=False)

        points_count = 12
        base_val = max(25.0, target_disk_percent - (slope_boost * (points_count - 1)))
        for i in range(points_count):
            t = now - timedelta(hours=(points_count - 1 - i))
            val = round(base_val + (i * slope_boost), 1)
            db.add(Metrique(equipement_id=equipement_id, type_metrique="disk_percent", valeur=val, horodatage=t))

        db.commit()

        pred = SupervisionService.calculate_ttf(db, equipement_id, metrique_cible="disk_percent")
        log_audit_action(
            db=db,
            action="SIMULATION_DISK_STRESS",
            cible=equipement.nom,
            details=f"Test de charge disque à {target_disk_percent}%. Nouveau TTF estimé: {pred.ttf_estime_heures if pred else 'N/A'}h",
        )
        return pred
