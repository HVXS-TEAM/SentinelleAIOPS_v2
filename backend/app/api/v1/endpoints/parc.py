"""Endpoints de l'API de Gestion de Parc Informatique et Inventaire."""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import Equipement, User, AuditReseau, Prediction, Alerte
from backend.app.schemas.parc import (
    EquipementOut, EquipementCreate, EquipementUpdate,
    SnmpScanRequest, SnmpScanResponse,
    LocalNetworkInfoOut, RealNetworkScanResponse, ImportRealDevicesRequest,
    SSHExecuteRequest, SSHExecuteResponse
)
from backend.app.modules.parc.service import ParcService
from backend.app.modules.parc.ssh_service import SSHExecutionService
from backend.app.core.security import encrypt_secret, decrypt_secret
from backend.app.api.deps import get_current_user, require_roles
from backend.app.core.audit import log_audit_action



router = APIRouter(prefix="/parc", tags=["Gestion de Parc & Inventaire"])


@router.get("/equipements", response_model=List[EquipementOut], summary="Inventaire complet du parc")
def list_equipements(
    groupe: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retourne la liste des équipements enregistrés avec filtrage optionnel par groupe."""
    query = db.query(Equipement)
    if groupe and groupe != "Tous":
        query = query.filter(Equipement.groupe == groupe)
    return query.order_by(Equipement.id.asc()).all()


@router.get("/equipements/{equipement_id}", summary="Fiche détaillée de l'équipement")
def get_equipement_detail(
    equipement_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retourne la fiche descriptive complète avec historique d'audits, prédictions et alertes."""
    eq = db.query(Equipement).filter(Equipement.id == equipement_id).first()
    if not eq:
        raise HTTPException(status_code=404, detail="Équipement introuvable")

    # Audits récents
    audits = db.query(AuditReseau).filter(AuditReseau.equipement_id == equipement_id).all()
    # Prédiction active
    prediction = db.query(Prediction).filter(Prediction.equipement_id == equipement_id).first()
    # Alertes actives
    alertes = db.query(Alerte).filter(Alerte.equipement_id == equipement_id, Alerte.statut == "Active").all()

    return {
        "equipement": EquipementOut.model_validate(eq),
        "audits_count": len(audits),
        "audits": audits,
        "prediction": prediction,
        "alertes_actives": alertes,
    }


@router.post("/equipements", response_model=EquipementOut, summary="Ajout d'un nouvel équipement")
def create_equipement(
    eq_in: EquipementCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """Enregistre un nouvel équipement avec chiffrement de ses identifiants."""
    existing = db.query(Equipement).filter(
        (Equipement.ip == eq_in.ip) | (Equipement.nom == eq_in.nom)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Un équipement avec cette IP ou ce nom existe déjà")

    encrypted_pwd = encrypt_secret(eq_in.mot_de_passe_secret) if eq_in.mot_de_passe_secret else None
    new_eq = Equipement(
        nom=eq_in.nom,
        ip=eq_in.ip,
        mac=eq_in.mac,
        type=eq_in.type,
        os=eq_in.os,
        firmware=eq_in.firmware,
        groupe=eq_in.groupe,
        seuil_disque_alerte=eq_in.seuil_disque_alerte,
        identifiants_chiffres=encrypted_pwd,
        score_sante=100.0,
        statut_collecte="OK",
    )
    db.add(new_eq)
    db.commit()
    db.refresh(new_eq)

    log_audit_action(
        db=db,
        action="CREATE_EQUIPEMENT",
        cible=f"{new_eq.nom} ({new_eq.ip})",
        user=current_user,
        details=f"Nouvel équipement {new_eq.type} ajouté au groupe {new_eq.groupe}",
    )
    return new_eq


@router.post("/scan-snmp", response_model=SnmpScanResponse, summary="Balayage réseau SNMP")
def trigger_snmp_scan(
    req: SnmpScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """Déclenche la découverte réseau SNMP et lève une alerte en cas d'équipement inconnu (Rogue)."""
    return ParcService.simulate_snmp_discovery(
        db,
        ip_range=req.plage_ip,
        inject_rogue=req.simuler_rogue_device,
    )


@router.get("/local-network-info", response_model=LocalNetworkInfoOut, summary="Informations réseau physique de l'hôte")
def get_local_network_info_endpoint(
    current_user: User = Depends(get_current_user),
):
    """Retourne l'adresse IP locale réelle de la machine hôte, son sous-réseau /24 et le nom d'hôte."""
    return ParcService.get_local_network_info()


@router.post("/scan-real", response_model=RealNetworkScanResponse, summary="Scan physique réel du sous-réseau local")
def trigger_real_network_scan(
    ip_prefix: Optional[str] = Query(default=None, description="Préfixe IP optionnel à balayer (ex: 192.168.0)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """Détecte les vrais équipements connectés sur le réseau local physique (Box, Switch, PCs, etc.)."""
    return ParcService.scan_real_network(db, ip_prefix=ip_prefix)


@router.post("/import-real-devices", summary="Importation des équipements physiques scannés")
def import_real_devices_endpoint(
    req: ImportRealDevicesRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """Enregistre en base de données les équipements réels sélectionnés après le scan physique."""
    devices_data = [dev.model_dump() for dev in req.devices]
    return ParcService.import_real_devices(db, devices_data)


@router.post("/ssh/execute", response_model=SSHExecuteResponse, summary="Exécution de commande SSH ou CLI")
def execute_ssh_command_endpoint(
    req: SSHExecuteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """Exécute une commande terminal via SSH Paramiko (réel) ou via le moteur CLI exhaustif."""
    ip = req.ip
    device_name = req.device_name or "device"
    password = req.password

    # Récupérer les informations de l'équipement si equipement_id est fourni
    if req.equipement_id:
        eq = db.query(Equipement).filter(Equipement.id == req.equipement_id).first()
        if eq:
            ip = eq.ip
            device_name = eq.nom
            if eq.identifiants_chiffres and not password:
                try:
                    password = decrypt_secret(eq.identifiants_chiffres)
                except Exception:
                    pass

    # Exécution via SSHExecutionService
    result = SSHExecutionService.execute(
        ip=ip,
        command=req.command,
        port=req.port,
        username=req.username or "admin",
        password=password,
        device_name=device_name,
    )

    log_audit_action(
        db=db,
        action="SSH_COMMAND_EXECUTE",
        cible=f"{device_name} ({ip})",
        user=current_user,
        details=f"Commande: {req.command} | Mode: {result['mode']}",
    )

    return result




@router.post("/recalculate-scores", summary="Recalcul des scores de santé")
def recalculate_health_scores(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Actualise les notes de santé (0 à 100) pour l'intégralité du parc."""
    scores = ParcService.recalculate_all_health_scores(db)
    return {"message": "Scores de santé recalculés avec succès", "scores": scores}


@router.get("/export-csv", summary="Export de l'inventaire en CSV")
def export_csv_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Génère et télécharge un fichier CSV d'inventaire complet."""
    csv_data = ParcService.export_csv(db)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=inventaire_parc_sentinelle.csv"},
    )


@router.delete("/equipements/{equipement_id}", summary="Suppression d'un équipement")
def delete_equipement(
    equipement_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur"])),
):
    """Supprime définitivement un équipement du parc et consigne l'action dans le journal d'audit."""
    eq = db.query(Equipement).filter(Equipement.id == equipement_id).first()
    if not eq:
        raise HTTPException(status_code=404, detail="Équipement introuvable")

    cible_info = f"{eq.nom} ({eq.ip})"
    db.delete(eq)
    db.commit()

    log_audit_action(
        db=db,
        action="DELETE_EQUIPEMENT",
        cible=cible_info,
        user=current_user,
        details=f"Suppression définitive de l'équipement #{equipement_id} du parc",
    )
    return {"message": f"Équipement {cible_info} supprimé avec succès"}

