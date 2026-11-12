"""
Endpoints REST – Module Administration, RBAC & Continuité d'Activité (PRA).

Routes :
  GET  /admin/users                    → Liste des utilisateurs et rôles RBAC
  POST /admin/users                    → Création d'un nouvel utilisateur
  PUT  /admin/users/{user_id}/status   → Activation/désactivation d'un compte
  GET  /admin/audit-logs               → Consultation du journal d'audit inaltérable
  POST /admin/pra/backup               → Déclenchement d'une sauvegarde à chaud
  GET  /admin/pra/backups              → Liste des sauvegardes avec statut SHA-256
  POST /admin/pra/verify/{filename}    → Contrôle d'intégrité d'une sauvegarde
  POST /admin/pra/restore/{filename}   → Restauration atomique d'une sauvegarde PRA
  GET  /admin/pra/metrics              → Métriques RTO / RPO de continuité
  GET  /admin/notifications/config     → Lecture de la configuration persistante d'alertes
  PUT  /admin/notifications/config     → Sauvegarde chiffrée de la configuration d'alertes
  POST /admin/environment/real-only    → Purge des nœuds démo & import du LAN physique réel
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import User
from backend.app.api.deps import get_current_user
from backend.app.modules.admin.service import AdminService
from backend.app.modules.admin.report_generator import generate_audit_pdf
from backend.app.modules.admin.notifications import NotificationService
from backend.app.schemas.admin import (
    CreateUserRequest,
    NotificationSettingsPayload,
    NotificationTestRequest,
    NotificationTestResponse,
    NotificationDispatchRequest,
    NotificationDispatchResponse,
)

router = APIRouter(prefix="/admin", tags=["Administration & PRA"])


@router.get("/users", summary="Liste des utilisateurs et rôles RBAC")
def get_users(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Retourne tous les comptes utilisateurs."""
    return AdminService.list_users(db)


@router.post("/users", summary="Création d'un compte utilisateur")
def create_new_user(user_in: CreateUserRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Crée un compte utilisateur avec hachage bcrypt."""
    try:
        return AdminService.create_user(
            db,
            identifiant=user_in.identifiant,
            email=user_in.email,
            nom_complet=user_in.nom_complet,
            mot_de_passe=user_in.mot_de_passe,
            role=user_in.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/users/{user_id}/status", summary="Activation/désactivation de compte")
def toggle_user_status(user_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Active ou désactive un compte utilisateur."""
    try:
        return AdminService.toggle_user_status(db, user_id=user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/audit-logs", summary="Journal d'audit inaltérable")
def get_audit_trail(
    limit: int = Query(default=100, ge=1, le=500),
    action: str | None = Query(default=None),
    search: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """Consulte le journal d'audit inaltérable."""
    return AdminService.get_audit_logs(db, limit=limit, action=action, search=search)


@router.post("/pra/backup", summary="Exécution d'une sauvegarde PRA à chaud")
def trigger_backup(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Déclenche une sauvegarde SQLite atomique avec empreinte SHA-256."""
    try:
        return AdminService.trigger_pra_backup(db)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur de sauvegarde PRA : {exc}") from exc


@router.get("/pra/backups", summary="Historique des sauvegardes et conformité SHA-256")
def list_backups() -> list[dict[str, Any]]:
    """Liste toutes les sauvegardes PRA disponibles."""
    return AdminService.list_pra_backups()


@router.post("/pra/verify/{filename}", summary="Vérification d'intégrité cryptographique SHA-256")
def verify_backup(filename: str) -> dict[str, Any]:
    """Vérifie l'empreinte SHA-256 d'un fichier de sauvegarde."""
    try:
        return AdminService.verify_backup_integrity(filename)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/pra/restore/{filename}", summary="Restauration à chaud d'une sauvegarde PRA")
def restore_backup(filename: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """
    Rôle : Restaure une sauvegarde SQLite après vérification cryptographique SHA-256.
    Entrées : filename, db.
    Sorties : Statut de restauration PRA.
    Cas d'erreur : 404 si fichier introuvable, 400 si empreinte SHA-256 invalide.
    """
    try:
        return AdminService.restore_pra_backup(db, filename=filename)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur de restauration PRA : {exc}") from exc


@router.get("/pra/metrics", summary="Indicateurs de continuité RTO et RPO")
def get_continuity_metrics() -> dict[str, Any]:
    """Retourne les métriques RTO / RPO du PRA."""
    return AdminService.get_pra_metrics()


@router.get("/reports/generate-pdf", summary="Génération d'un rapport d'audit PDF certifié")
def download_audit_report_pdf(
    title: str = Query(default="Rapport d'Audit Global et Résilience"),
    scope: str = Query(default="Infrastructure Globale"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Génère dynamiquement un rapport d'audit PDF à partir des données réelles SQLite."""
    pdf_bytes = generate_audit_pdf(
        db=db,
        title=title,
        author=current_user.nom_complet if current_user else "Administrateur",
        scope=scope,
    )
    safe_filename = title.lower().replace(" ", "_").replace("'", "")[:40]
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=sentinelle_{safe_filename}.pdf"
        },
    )


@router.get("/notifications/config", summary="Lecture de la configuration persistante des notifications")
def get_notification_config() -> dict[str, Any]:
    """Retourne la configuration persistée des canaux Telegram, Discord et SMTP."""
    return AdminService.get_notification_settings()


@router.put("/notifications/config", summary="Sauvegarde de la configuration des notifications")
def save_notification_config(
    payload: NotificationSettingsPayload,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Sauvegarde et chiffre la configuration des canaux d'alerte sur le serveur."""
    return AdminService.save_notification_settings(db, payload.model_dump())


@router.post("/notifications/test", response_model=NotificationTestResponse, summary="Test d'un canal de notification")
def test_notification_channel(
    req: NotificationTestRequest,
    current_user: User = Depends(get_current_user),
) -> NotificationTestResponse:
    """Effectue un test d'envoi réel sur Telegram, Discord ou SMTP."""
    if req.channel == "discord":
        if not req.discord_config:
            raise HTTPException(status_code=400, detail="Configuration Discord manquante")
        return NotificationService.test_discord(req.discord_config, req.message)
    elif req.channel == "telegram":
        if not req.telegram_config:
            raise HTTPException(status_code=400, detail="Configuration Telegram manquante")
        return NotificationService.test_telegram(req.telegram_config, req.message)
    elif req.channel == "email":
        if not req.email_config:
            raise HTTPException(status_code=400, detail="Configuration Email SMTP manquante")
        return NotificationService.test_email(req.email_config, req.message)
    raise HTTPException(status_code=400, detail="Canal non supporté")


@router.post("/notifications/dispatch", response_model=NotificationDispatchResponse, summary="Dispatch d'alerte multi-canaux")
def dispatch_alert(
    req: NotificationDispatchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NotificationDispatchResponse:
    """Diffuse une alerte vers l'ensemble des canaux sélectionnés et consigne au journal d'audit."""
    return NotificationService.dispatch_alert(req, db=db, current_user=current_user)


@router.post("/environment/real-only", summary="Bascule en mode 100 % Réseau Physique Réel")
def switch_to_real_network_only(db: Session = Depends(get_db)) -> dict[str, Any]:
    """
    Rôle : Purge les équipements fictifs de démonstration, conserve l'hôte local réel,
    scanne le réseau physique (ARP/ICMP/TCP) et importe les équipements réels détectés.
    """
    return AdminService.reset_to_real_network_only(db)
