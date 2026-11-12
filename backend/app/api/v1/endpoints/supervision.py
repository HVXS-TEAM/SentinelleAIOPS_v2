"""Endpoints de l'API de Supervision Prédictive, Métrologie et Cycle de Vie des Alertes."""
import socket
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import Equipement, Metrique, Prediction, User
from backend.app.schemas.supervision import (
    MetricSeriesResponse,
    PredictionOut,
    AlerteOut,
    DiskStressRequest,
    ThresholdUpdateRequest,
)
from backend.app.modules.supervision.service import SupervisionService
from backend.app.modules.supervision.hardware_collector import HardwareCollector
from backend.app.api.deps import get_current_user, require_roles
from backend.app.core.audit import log_audit_action

router = APIRouter(prefix="/supervision", tags=["Supervision Prédictive & Métrologie"])


@router.get("/hardware/live", summary="Télémétrie matérielle réelle de la machine hôte")
def get_hardware_live(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Rôle : Retourne les métriques matérielles en temps réel (CPU, RAM, Disque, Réseau) de la machine hôte.
    Entrées : Session DB, utilisateur courant.
    Sorties : Dictionnaire de télémétrie matérielle.
    """
    return HardwareCollector.collect_live_metrics(db)


@router.get("/metrics/{equipement_id}", response_model=MetricSeriesResponse, summary="Historique des métriques")
def get_metrics(
    equipement_id: int,
    type_metrique: str = Query(default="disk_percent", description="Type de métrique: cpu_percent, ram_percent, disk_percent, network_mbps"),
    limit: int = Query(default=48, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Rôle : Retourne la série chronologique réelle d'un équipement pour l'affichage des graphiques Recharts.
    Entrées : ID équipement, type de métrique, nombre maximal de points.
    Sorties : Objet MetricSeriesResponse ordonné chronologiquement.
    Cas d'erreur : HTTP 404 si l'équipement est introuvable.
    """
    equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
    if not equipement:
        raise HTTPException(status_code=404, detail="Équipement introuvable")

    if equipement.groupe == "Hôte Local (Hardware)" or equipement.nom == socket.gethostname():
        HardwareCollector.collect_live_metrics(db)

    records = (
        db.query(Metrique)
        .filter(
            Metrique.equipement_id == equipement_id,
            Metrique.type_metrique == type_metrique,
        )
        .order_by(Metrique.horodatage.desc())
        .limit(limit)
        .all()
    )

    # Si l'équipement ne possède encore aucune mesure pour cette métrique, déclencher une sonde immédiate
    if not records:
        from backend.app.modules.parc.service import ParcService
        ParcService.probe_equipment(db, equipement)
        records = (
            db.query(Metrique)
            .filter(
                Metrique.equipement_id == equipement_id,
                Metrique.type_metrique == type_metrique,
            )
            .order_by(Metrique.horodatage.desc())
            .limit(limit)
            .all()
        )

    records.reverse()

    return {
        "equipement_id": equipement.id,
        "equipement_nom": equipement.nom,
        "type_metrique": type_metrique,
        "points": records,
    }


@router.get("/predictions", response_model=List[PredictionOut], summary="Liste des prédictions TTF")
def list_predictions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Rôle : Retourne l'état prédictif de saturation (Time-To-Failure) pour tous les équipements supervisés.
    Entrées : Session DB, utilisateur courant.
    Sorties : Liste de PredictionOut.
    """
    predictions = db.query(Prediction).order_by(Prediction.date_calcul.desc()).all()
    result = []
    for p in predictions:
        item = PredictionOut.model_validate(p)
        item.equipement_nom = p.equipement.nom if p.equipement else f"ID-{p.equipement_id}"
        result.append(item)
    return result


@router.get("/alerts", response_model=List[AlerteOut], summary="Liste des alertes opérationnelles")
def get_alerts(
    statut: Optional[str] = Query(default=None, description="Filtrer par statut: Active, Acquittée, Résolue, Toutes"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Rôle : Retourne la liste des alertes avec filtrage par statut.
    Entrées : Statut optionnel, limite, session DB.
    Sorties : Liste d'alertes enrichies.
    """
    return SupervisionService.list_alerts(db, statut=statut, limit=limit)


@router.put("/alerts/{alerte_id}/acknowledge", response_model=AlerteOut, summary="Acquitter une alerte")
def acknowledge_alert_endpoint(
    alerte_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """
    Rôle : Acquitte officiellement une alerte active.
    Entrées : ID de l'alerte, utilisateur authentifié.
    Sorties : AlerteOut mise à jour.
    Cas d'erreur : HTTP 404 si l'alerte n'existe pas.
    """
    try:
        alerte = SupervisionService.acknowledge_alert(db, alerte_id, user=current_user)
        out = AlerteOut.model_validate(alerte)
        out.equipement_nom = alerte.equipement.nom if alerte.equipement else "Système"
        return out
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/alerts/{alerte_id}/resolve", response_model=AlerteOut, summary="Résoudre et clôturer une alerte")
def resolve_alert_endpoint(
    alerte_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """
    Rôle : Marque une alerte comme résolue et recalcule le score de santé de l'équipement.
    Entrées : ID de l'alerte, utilisateur authentifié.
    Sorties : AlerteOut résolue.
    Cas d'erreur : HTTP 404 si l'alerte n'existe pas.
    """
    try:
        alerte = SupervisionService.resolve_alert(db, alerte_id, user=current_user)
        out = AlerteOut.model_validate(alerte)
        out.equipement_nom = alerte.equipement.nom if alerte.equipement else "Système"
        return out
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/probe-all", summary="Sonder immédiatement tous les équipements du parc")
def probe_all_equipments_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """
    Rôle : Déclenche une sonde immédiate (Ping / TCP / SSH / psutil) sur l'ensemble du parc.
    Entrées : Session DB, utilisateur authentifié.
    Sorties : Bilan du cycle de collecte.
    """
    from backend.app.modules.parc.service import ParcService
    return ParcService.probe_all_equipments(db)


@router.post("/recalculate/{equipement_id}", response_model=PredictionOut, summary="Recalcul manuel TTF")
def recalculate_ttf(
    equipement_id: int,
    metrique: str = "disk_percent",
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """Exécute l'algorithme de régression linéaire et met à jour le TTF."""
    pred = SupervisionService.calculate_ttf(db, equipement_id, metrique_cible=metrique)
    if not pred:
        raise HTTPException(status_code=400, detail="Données insuffisantes pour ajuster le modèle prédictif")
    item = PredictionOut.model_validate(pred)
    item.equipement_nom = pred.equipement.nom if pred.equipement else ""
    return item


@router.post("/simulate-stress", response_model=PredictionOut, summary="Test de charge disque & Alerte TTF")
def simulate_disk_stress_endpoint(
    req: DiskStressRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """Injecte une accélération de la consommation disque et recalcule immédiatement le TTF."""
    try:
        pred = SupervisionService.simulate_disk_stress(
            db,
            equipement_id=req.equipement_id,
            target_disk_percent=req.target_disk_percent,
            slope_boost=req.slope_boost,
        )
        item = PredictionOut.model_validate(pred)
        item.equipement_nom = pred.equipement.nom if pred.equipement else ""
        return item
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/threshold/{equipement_id}", summary="Configuration du seuil d'alerte")
def update_threshold(
    equipement_id: int,
    req: ThresholdUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """Ajuste le seuil critique personnalisé de l'équipement et recalcule le TTF associé."""
    equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
    if not equipement:
        raise HTTPException(status_code=404, detail="Équipement introuvable")

    ancien_seuil = equipement.seuil_disque_alerte
    equipement.seuil_disque_alerte = req.seuil_disque_alerte
    db.commit()

    # Recalculer immédiatement le TTF avec le nouveau seuil
    SupervisionService.calculate_ttf(db, equipement_id, metrique_cible="disk_percent")

    log_audit_action(
        db=db,
        action="UPDATE_THRESHOLD",
        cible=equipement.nom,
        user=current_user,
        details=f"Seuil disque modifié de {ancien_seuil}% à {req.seuil_disque_alerte}%",
    )
    return {
        "message": "Seuil d'alerte mis à jour avec succès",
        "equipement": equipement.nom,
        "nouveau_seuil": equipement.seuil_disque_alerte,
    }
