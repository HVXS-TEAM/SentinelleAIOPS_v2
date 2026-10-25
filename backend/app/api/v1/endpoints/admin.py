"""
Endpoints REST – Module Administration, RBAC & Continuité d'Activité (PRA).

Routes :
  GET  /admin/users                 → Liste des utilisateurs et rôles RBAC
  POST /admin/users                 → Création d'un nouvel utilisateur
  PUT  /admin/users/{user_id}/status → Activation/désactivation d'un compte
  GET  /admin/audit-logs            → Consultation du journal d'audit inaltérable
  POST /admin/pra/backup            → Déclenchement d'une sauvegarde à chaud
  GET  /admin/pra/backups           → Liste des sauvegardes avec statut SHA-256
  POST /admin/pra/verify/{filename} → Contrôle d'intégrité d'une sauvegarde
  GET  /admin/pra/metrics           → Métriques RTO / RPO de continuité
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, EmailStr, Field
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import User
from backend.app.api.deps import get_current_user
from backend.app.modules.admin.service import AdminService
from backend.app.modules.admin.report_generator import generate_audit_pdf
from backend.app.modules.admin.notifications import NotificationService
from backend.app.schemas.admin import (
    NotificationTestRequest,
    NotificationTestResponse,
    NotificationDispatchRequest,
    NotificationDispatchResponse,
)

router = APIRouter(prefix="/admin", tags=["Administration & PRA"])


class CreateUserRequest(BaseModel):
    identifiant: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    nom_complet: str = Field(..., min_length=2, max_length=100)
    mot_de_passe: str = Field(..., min_length=8)
    role: str = Field(default="Technicien", pattern="^(Administrateur|Technicien|Visiteur)$")


@router.get("/users", summary="Liste des utilisateurs et rôles RBAC")
def get_users(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return AdminService.list_users(db)


@router.post("/users", summary="Création d'un compte utilisateur")
def create_new_user(user_in: CreateUserRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
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
    return AdminService.get_audit_logs(db, limit=limit, action=action, search=search)


@router.post("/pra/backup", summary="Exécution d'une sauvegarde PRA à chaud")
def trigger_backup(db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        return AdminService.trigger_pra_backup(db)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur de sauvegarde PRA : {exc}") from exc


@router.get("/pra/backups", summary="Historique des sauvegardes et conformité SHA-256")
def list_backups() -> list[dict[str, Any]]:
    return AdminService.list_pra_backups()


@router.post("/pra/verify/{filename}", summary="Vérification d'intégrité cryptographique SHA-256")
def verify_backup(filename: str) -> dict[str, Any]:
    try:
        return AdminService.verify_backup_integrity(filename)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/pra/metrics", summary="Indicateurs de continuité RTO et RPO")
def get_continuity_metrics() -> dict[str, Any]:
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

