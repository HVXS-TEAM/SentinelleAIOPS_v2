"""Schémas Pydantic pour la cybersécurité et l'analyse de logs AIOps."""
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class EvenementSecuriteOut(BaseModel):
    id: int
    equipement_id: Optional[int] = None
    source_ip: str
    source_ip_anonymisee: str
    utilisateur_cible: Optional[str] = None
    type_evenement: str
    score_anomalie: float
    severite: str
    is_anomaly: bool
    explication: Optional[str] = None
    tentatives_minute: int
    horodatage: datetime

    model_config = ConfigDict(from_attributes=True)


class AnalyzeBatchRequest(BaseModel):
    equipement_id: Optional[int] = None
    logs: List[str] = Field(description="Liste de lignes de journal auth.log ou Syslog à analyser")


class BruteForceSimulationRequest(BaseModel):
    equipement_id: int
    attacker_ip: str = "198.51.100.45"


class SecurityStatsResponse(BaseModel):
    total_evenements: int
    total_anomalies: int
    attaques_critiques: int
    taux_precision_ia: float
    baseline_accord_pct: float
