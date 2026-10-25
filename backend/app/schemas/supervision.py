"""Schémas Pydantic pour la supervision, les métriques et les prédictions TTF."""
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List
from datetime import datetime


class MetricOut(BaseModel):
    id: int
    equipement_id: int
    type_metrique: str
    valeur: float
    horodatage: datetime

    model_config = ConfigDict(from_attributes=True)


class MetricSeriesResponse(BaseModel):
    equipement_id: int
    equipement_nom: str
    type_metrique: str
    points: List[MetricOut]


class PredictionOut(BaseModel):
    id: int
    equipement_id: int
    equipement_nom: Optional[str] = None
    metrique: str
    valeur_actuelle: float
    pente_horaire: float
    r2_score: float
    mape_erreur: Optional[float] = None
    indice_confiance: str
    ttf_estime_heures: Optional[float] = None
    date_saturation_estimee: Optional[datetime] = None
    date_calcul: datetime

    model_config = ConfigDict(from_attributes=True)


class DiskStressRequest(BaseModel):
    equipement_id: int
    target_disk_percent: float = Field(default=89.0, ge=50.0, le=99.0)
    slope_boost: float = Field(default=2.5, ge=0.5, le=10.0)


class ThresholdUpdateRequest(BaseModel):
    seuil_disque_alerte: float = Field(ge=50.0, le=99.0)
