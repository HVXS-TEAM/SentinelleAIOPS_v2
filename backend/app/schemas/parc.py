"""Schémas Pydantic pour la gestion de parc et l'inventaire."""
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class EquipementBase(BaseModel):
    nom: str
    ip: str
    mac: Optional[str] = None
    type: str
    os: Optional[str] = None
    firmware: Optional[str] = None
    groupe: str = "Production"
    seuil_disque_alerte: float = 85.0


class EquipementCreate(EquipementBase):
    mot_de_passe_secret: Optional[str] = None  # Mot de passe à chiffrer via Fernet


class EquipementUpdate(BaseModel):
    nom: Optional[str] = None
    ip: Optional[str] = None
    groupe: Optional[str] = None
    seuil_disque_alerte: Optional[float] = None
    statut_collecte: Optional[str] = None


class EquipementOut(EquipementBase):
    id: int
    uptime_secondes: int
    score_sante: float
    statut_collecte: str
    date_decouverte: datetime
    derniere_collecte: datetime

    model_config = ConfigDict(from_attributes=True)


class SnmpScanRequest(BaseModel):
    plage_ip: str = "192.168.1.0/24"
    simuler_rogue_device: bool = False


class SnmpScanResponse(BaseModel):
    plage: str
    equipements_actifs: List[str]
    nouveaux_detectes: int
    rogue_device: Optional[Dict[str, Any]] = None
    horodatage: str


class LocalNetworkInfoOut(BaseModel):
    local_ip: str
    subnet: str
    hostname: str
    gateway_ip: Optional[str] = None
    interface_name: Optional[str] = None


class DiscoveredDeviceOut(BaseModel):
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    type: str
    os: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    banner: Optional[str] = None
    already_in_parc: bool = False


class RealNetworkScanResponse(BaseModel):
    subnet: str
    local_host: LocalNetworkInfoOut
    devices_count: int
    devices: List[DiscoveredDeviceOut]
    scan_duration_ms: int


class DeviceImportItem(BaseModel):
    nom: str
    ip: str
    mac: Optional[str] = None
    type: str
    os: Optional[str] = None
    groupe: str = "Physique"


class ImportRealDevicesRequest(BaseModel):
    devices: List[DeviceImportItem]


class SSHExecuteRequest(BaseModel):
    equipement_id: Optional[int] = None
    ip: str
    port: int = 22
    username: Optional[str] = "admin"
    password: Optional[str] = None
    command: str
    device_name: Optional[str] = "device"


class SSHExecuteResponse(BaseModel):
    output: str
    exit_code: int
    mode: str
    device: str
    horodatage: str


