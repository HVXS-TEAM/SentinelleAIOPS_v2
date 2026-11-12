"""Schémas Pydantic pour la gestion de parc, l'inventaire et la télémétrie par équipement."""
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class EquipementBase(BaseModel):
    """Attributs de base d'un équipement réseau ou serveur."""
    nom: str
    ip: str
    mac: Optional[str] = None
    type: str
    os: Optional[str] = None
    firmware: Optional[str] = None
    groupe: str = "Production"
    seuil_disque_alerte: float = 85.0


class EquipementCreate(EquipementBase):
    """Schéma de création d'un équipement avec secret SSH/SNMP optionnel."""
    mot_de_passe_secret: Optional[str] = None  # Identifiant:MotDePasse ou MotDePasse chiffré via Fernet


class EquipementUpdate(BaseModel):
    """Schéma de mise à jour partielle d'un équipement existant."""
    nom: Optional[str] = None
    ip: Optional[str] = None
    mac: Optional[str] = None
    type: Optional[str] = None
    os: Optional[str] = None
    firmware: Optional[str] = None
    groupe: Optional[str] = None
    seuil_disque_alerte: Optional[float] = None
    statut_collecte: Optional[str] = None
    mot_de_passe_secret: Optional[str] = None


class EquipementOut(EquipementBase):
    """Schéma de sortie enrichi avec les dernières métriques réelles collectées en base."""
    id: int
    uptime_secondes: int
    score_sante: float
    statut_collecte: str
    date_decouverte: datetime
    derniere_collecte: datetime
    cpu_percent: Optional[float] = None
    ram_percent: Optional[float] = None
    disk_percent: Optional[float] = None
    network_mbps: Optional[float] = None
    cpu_history: List[float] = Field(default_factory=list)
    ram_history: List[float] = Field(default_factory=list)
    active_alerts_count: int = 0
    has_ssh_credentials: bool = False
    cis_status: str = "ok"
    cis_message: str = "Conforme CIS Benchmark"
    last_backup: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class SnmpScanRequest(BaseModel):
    """Requête de balayage réseau et détection d'équipements."""
    plage_ip: str = "192.168.1.0/24"
    simuler_rogue_device: bool = False


class SnmpScanResponse(BaseModel):
    """Résultat d'un balayage réseau SNMP/ARP."""
    plage: str
    equipements_actifs: List[str]
    nouveaux_detectes: int
    rogue_device: Optional[Dict[str, Any]] = None
    horodatage: str


class LocalNetworkInfoOut(BaseModel):
    """Informations sur l'interface réseau physique de l'hôte."""
    local_ip: str
    subnet: str
    hostname: str
    gateway_ip: Optional[str] = None
    interface_name: Optional[str] = None


class DiscoveredDeviceOut(BaseModel):
    """Équipement physique découvert sur le réseau local."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    type: str
    os: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    banner: Optional[str] = None
    already_in_parc: bool = False


class RealNetworkScanResponse(BaseModel):
    """Réponse complète d'un scan réseau physique LAN."""
    subnet: str
    local_host: LocalNetworkInfoOut
    devices_count: int
    devices: List[DiscoveredDeviceOut]
    scan_duration_ms: int


class DeviceImportItem(BaseModel):
    """Élément à importer dans le parc suite à un scan physique."""
    nom: str
    ip: str
    mac: Optional[str] = None
    type: str
    os: Optional[str] = None
    groupe: str = "Physique"


class ImportRealDevicesRequest(BaseModel):
    """Lot d'équipements physiques à importer dans SQLite."""
    devices: List[DeviceImportItem]


class SSHExecuteRequest(BaseModel):
    """Requête d'exécution de commande distante SSH ou diagnostic système."""
    equipement_id: Optional[int] = None
    ip: str
    port: int = 22
    username: Optional[str] = "admin"
    password: Optional[str] = None
    command: str
    device_name: Optional[str] = "device"


class SSHExecuteResponse(BaseModel):
    """Résultat d'exécution d'une commande SSH ou CLI."""
    output: str
    exit_code: int
    mode: str
    device: str
    horodatage: str
