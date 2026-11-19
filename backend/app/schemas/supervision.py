"""Schémas Pydantic pour la supervision, les métriques, les prédictions TTF et le cycle de vie des alertes."""
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List
from datetime import datetime


class MetricOut(BaseModel):
    """Représentation d'un point de mesure télémétrique."""
    id: int
    equipement_id: int
    type_metrique: str
    valeur: float
    horodatage: datetime

    model_config = ConfigDict(from_attributes=True)


class MetricSeriesResponse(BaseModel):
    """Série temporelle complète pour un équipement et un type de métrique."""
    equipement_id: int
    equipement_nom: str
    type_metrique: str
    points: List[MetricOut]


class PredictionOut(BaseModel):
    """Résultat du modèle prédictif linéaire Time-To-Failure (TTF)."""
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


class AlerteOut(BaseModel):
    """Schéma de sortie d'une alerte opérationnelle avec son état d'acquittement."""
    id: int
    equipement_id: Optional[int] = None
    equipement_nom: Optional[str] = None
    module_origine: str
    severite: str
    titre: str
    message: str
    statut: str
    correlation_id: Optional[str] = None
    date_creation: datetime
    date_acquittement: Optional[datetime] = None
    acquittee_par: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ThresholdUpdateRequest(BaseModel):
    """Mise à jour du seuil critique d'alerte disque d'un équipement."""
    seuil_disque_alerte: float = Field(ge=50.0, le=99.0)
