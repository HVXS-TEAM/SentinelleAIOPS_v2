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
    """Lot de lignes de journaux (sshd, Cisco IOS) à analyser, sans enregistrement."""
    equipement_id: Optional[int] = None
    logs: List[str] = Field(description="Lignes de journal sshd (auth.log, journald) ou Cisco IOS (%SEC_LOGIN) à analyser")


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
    ips_bloquees: int = 0
    modele_actif: str = "regles_statiques"
    echantillons_baseline: int = 0
    echantillons_requis: int = 0
    evenements_par_source: Dict[str, int] = Field(default_factory=dict)
    derniere_observation: Optional[datetime] = None
    syslog_actif: bool = False
    syslog_datagrammes_recus: int = 0
    syslog_ignores_source_inconnue: int = 0
    connexions_actives_hote: int = 0
    ports_ecoute_hote: int = 0
