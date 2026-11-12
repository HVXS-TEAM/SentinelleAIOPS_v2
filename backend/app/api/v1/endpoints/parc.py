"""Endpoints de l'API de Gestion de Parc Informatique, Inventaire et Sonde Active."""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import Equipement, User, AuditReseau, Prediction, Alerte
from backend.app.schemas.parc import (
    EquipementOut,
    EquipementCreate,
    EquipementUpdate,
    SnmpScanRequest,
    SnmpScanResponse,
    LocalNetworkInfoOut,
    RealNetworkScanResponse,
    ImportRealDevicesRequest,
    SSHExecuteRequest,
    SSHExecuteResponse,
)
from backend.app.modules.parc.service import ParcService
from backend.app.modules.parc.ssh_service import SSHExecutionService
from backend.app.modules.supervision.hardware_collector import HardwareCollector
from backend.app.core.security import encrypt_secret, decrypt_secret
from backend.app.api.deps import get_current_user, require_roles
from backend.app.core.audit import log_audit_action

router = APIRouter(prefix="/parc", tags=["Gestion de Parc & Inventaire"])


@router.get("/equipements", response_model=List[EquipementOut], summary="Inventaire complet du parc avec métriques temps réel")
def list_equipements(
    groupe: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Rôle : Retourne la liste des équipements enregistrés enrichis de leurs dernières métriques réelles.
           Garantit que la machine hôte réelle est toujours enregistrée et à jour.
    Entrées : Filtre optionnel par groupe, session DB, utilisateur authentifié.
    Sorties : Liste d'objets EquipementOut.
    """
    try:
        HardwareCollector.get_or_create_host_equipment(db)
    except Exception:
        pass

    query = db.query(Equipement)
    if groupe and groupe != "Tous":
        query = query.filter(Equipement.groupe == groupe)
    equipements = query.order_by(Equipement.id.asc()).all()
    return [ParcService.enrich_equipement(db, eq) for eq in equipements]


@router.get("/equipements/{equipement_id}", summary="Fiche détaillée de l'équipement")
def get_equipement_detail(
    equipement_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Rôle : Retourne la fiche descriptive complète avec métriques, audits CIS, prédictions TTF et alertes actives.
    Entrées : ID équipement, session DB, utilisateur authentifié.
    Sorties : Dictionnaire détaillé de l'équipement.
    Cas d'erreur : HTTP 404 si l'équipement est introuvable.
    """
    eq = db.query(Equipement).filter(Equipement.id == equipement_id).first()
    if not eq:
        raise HTTPException(status_code=404, detail="Équipement introuvable")

    audits = db.query(AuditReseau).filter(AuditReseau.equipement_id == equipement_id).all()
    prediction = db.query(Prediction).filter(Prediction.equipement_id == equipement_id).first()
    alertes = db.query(Alerte).filter(Alerte.equipement_id == equipement_id, Alerte.statut == "Active").all()

    return {
        "equipement": ParcService.enrich_equipement(db, eq),
        "audits_count": len(audits),
        "audits": audits,
        "prediction": prediction,
        "alertes_actives": alertes,
    }


@router.post("/equipements", response_model=EquipementOut, summary="Ajout d'un nouvel équipement et sonde initiale")
def create_equipement(
    eq_in: EquipementCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """
    Rôle : Enregistre un nouvel équipement avec chiffrement Fernet de ses identifiants SSH/SNMP
           et déclenche immédiatement sa première sonde réseau.
    Entrées : Payload EquipementCreate, session DB, utilisateur authentifié.
    Sorties : EquipementOut enrichi.
    Cas d'erreur : HTTP 400 en cas de doublon d'IP ou de nom.
    """
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

    try:
        ParcService.probe_equipment(db, new_eq)
    except Exception:
        pass

    log_audit_action(
        db=db,
        action="CREATE_EQUIPEMENT",
        cible=f"{new_eq.nom} ({new_eq.ip})",
        user=current_user,
        details=f"Nouvel équipement {new_eq.type} ajouté au groupe {new_eq.groupe}",
    )
    return ParcService.enrich_equipement(db, new_eq)


@router.put("/equipements/{equipement_id}", response_model=EquipementOut, summary="Mise à jour d'un équipement")
def update_equipement_endpoint(
    equipement_id: int,
    eq_in: EquipementUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """
    Rôle : Modifie les paramètres d'un équipement existant (IP, nom, seuil, identifiants SSH).
    Entrées : ID équipement, payload EquipementUpdate, session DB, utilisateur authentifié.
    Sorties : EquipementOut mis à jour.
    Cas d'erreur : HTTP 404 si l'équipement est introuvable.
    """
    try:
        updated = ParcService.update_equipement(
            db,
            equipement_id=equipement_id,
            update_data=eq_in.model_dump(exclude_unset=True),
            user=current_user,
        )
        return ParcService.enrich_equipement(db, updated)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/equipements/{equipement_id}/probe", summary="Sonder immédiatement un équipement spécifique")
def probe_single_equipement(
    equipement_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """
    Rôle : Exécute une sonde temps réel (psutil / Ping / TCP / SSH) sur un équipement précis.
    Entrées : ID équipement, session DB.
    Sorties : Résultat détaillé de la sonde et équipement mis à jour.
    """
    eq = db.query(Equipement).filter(Equipement.id == equipement_id).first()
    if not eq:
        raise HTTPException(status_code=404, detail="Équipement introuvable")
    probe_res = ParcService.probe_equipment(db, eq)
    return {
        "probe": probe_res,
        "equipement": ParcService.enrich_equipement(db, eq),
    }


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
    """Exécute une commande terminal via SSH Paramiko (réel), diagnostic hôte réel, ou moteur CLI."""
    ip = req.ip
    device_name = req.device_name or "device"
    password = req.password

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
