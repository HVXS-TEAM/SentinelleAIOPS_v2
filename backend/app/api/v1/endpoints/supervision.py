"""Endpoints de l'API de Supervision Prédictive et Métrologie."""
import socket
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import Equipement, Metrique, Prediction, User
from backend.app.schemas.supervision import (
    MetricOut, MetricSeriesResponse, PredictionOut,
    DiskStressRequest, ThresholdUpdateRequest
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
    """Retourne les métriques matérielles en temps réel (CPU, RAM, Disque, Réseau) de la machine hôte."""
    return HardwareCollector.collect_live_metrics(db)


@router.get("/metrics/{equipement_id}", response_model=MetricSeriesResponse, summary="Historique des métriques")
def get_metrics(
    equipement_id: int,
    type_metrique: str = Query(default="disk_percent", description="Type de métrique: cpu_percent, ram_percent, disk_percent"),
    limit: int = Query(default=48, ge=5, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retourne la série chronologique pour l'affichage des graphiques Recharts/Plotly."""
    equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
    if not equipement:
        raise HTTPException(status_code=404, detail="Équipement introuvable")

    if equipement.groupe == "Hôte Local (Hardware)" or equipement.nom == socket.gethostname():
        # Injecte une mesure matérielle instantanée
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
    records.reverse()  # Ordre chronologique croissant pour affichage courbe

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
    """Retourne l'état prédictif de saturation (Time-To-Failure) pour tous les serveurs."""
    predictions = db.query(Prediction).all()
    result = []
    for p in predictions:
        item = PredictionOut.model_validate(p)
        item.equipement_nom = p.equipement.nom if p.equipement else f"ID-{p.equipement_id}"
        result.append(item)
    return result


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


@router.post("/simulate-stress", response_model=PredictionOut, summary="Simulation Démo : Stress Disque")
def simulate_disk_stress_endpoint(
    req: DiskStressRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """Simule une accélération de la consommation disque et recalcule immédiatement le TTF."""
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
    current_user: User = Depends(require_roles(["Administrateur"])),
):
    """Ajuste le seuil critique personnalisé de l'équipement (Rôle Administrateur requis)."""
    equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
    if not equipement:
        raise HTTPException(status_code=404, detail="Équipement introuvable")

    ancien_seuil = equipement.seuil_disque_alerte
    equipement.seuil_disque_alerte = req.seuil_disque_alerte
    db.commit()

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
