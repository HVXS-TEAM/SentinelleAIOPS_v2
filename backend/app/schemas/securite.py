"""Schémas Pydantic pour la cybersécurité, l'analyse de logs AIOps et le pare-feu actif."""
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class EvenementSecuriteOut(BaseModel):
    """Événement de sécurité détecté par Isolation Forest ou sonde système."""
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
    """Lot de lignes de journaux à soumettre au moteur Isolation Forest."""
    equipement_id: Optional[int] = None
    logs: List[str] = Field(description="Liste de lignes de journal auth.log, Windows EventLog ou Syslog à analyser")


class BruteForceSimulationRequest(BaseModel):
    """Requête d'injection de test d'intrusion SSH pour vérification de la corrélation."""
    equipement_id: int
    attacker_ip: str = "198.51.100.45"


class BlockIpRequest(BaseModel):
    """Requête de blocage pare-feu d'une adresse IP malveillante."""
    source_ip: str
    incident_id: Optional[int] = None
    equipement_id: Optional[int] = None
    motif: Optional[str] = "Blocage manuel opérateur SOC"


class IsolateDeviceRequest(BaseModel):
    """Requête d'isolement réseau d'un équipement compromis."""
    equipement_id: Optional[int] = None
    device_name: str
    motif: Optional[str] = "Isolement préventif suite à alerte critique"


class SecurityStatsResponse(BaseModel):
    """Statistiques temps réel du moteur de cybersécurité Isolation Forest."""
    total_evenements: int
    total_anomalies: int
    attaques_critiques: int
    taux_precision_ia: float
    baseline_accord_pct: float
    connexions_actives_hote: int = 0
    ports_ecoute_hote: int = 0
