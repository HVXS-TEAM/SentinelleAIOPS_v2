"""
Endpoints REST – Module Administration, RBAC & Continuité d'Activité (PRA).

Routes :
  GET  /admin/users                    → Liste des utilisateurs et rôles RBAC
  POST /admin/users                    → Création d'un nouvel utilisateur
  PUT  /admin/users/{user_id}/status   → Activation/désactivation d'un compte
  PUT  /admin/users/{user_id}/role     → Changement du rôle RBAC d'un compte
  POST /admin/users/{user_id}/mfa/reset → Réinitialise le MFA d'un compte (appareil perdu)
  GET  /admin/audit-logs               → Consultation du journal d'audit inaltérable
  POST /admin/pra/backup               → Déclenchement d'une sauvegarde à chaud
  GET  /admin/pra/backups              → Liste des sauvegardes avec statut SHA-256
  POST /admin/pra/verify/{filename}    → Contrôle d'intégrité d'une sauvegarde
  POST /admin/pra/restore/{filename}   → Restauration atomique d'une sauvegarde PRA
  GET  /admin/pra/metrics              → Métriques RTO / RPO de continuité
  GET  /admin/notifications/config     → Lecture de la configuration persistante d'alertes
  PUT  /admin/notifications/config     → Sauvegarde chiffrée de la configuration d'alertes
  GET  /admin/ssh/known-hosts          → Clés d'hôte SSH épinglées (empreintes SHA-256)
  DELETE /admin/ssh/known-hosts/{hote} → Oublie la clé d'un hôte (après remplacement légitime)
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.db.models import User
from backend.app.api.deps import ROLES_ADMIN, ROLES_OPERATEURS, get_current_user, require_roles
from backend.app.core import mfa, ssh_trust
from backend.app.core.audit import log_audit_action
from backend.app.core.security import get_password_hash
from backend.app.api.v1.endpoints.auth import check_password_policy
from backend.app.modules.admin.service import AdminService
from backend.app.modules.admin.report_generator import generate_audit_pdf
from backend.app.modules.admin.notifications import NotificationService
from backend.app.schemas.admin import (
    CreateUserRequest,
    ResetPasswordRequest,
    UpdateUserRoleRequest,
    NotificationSettingsPayload,
    NotificationTestRequest,
    NotificationTestResponse,
    NotificationDispatchRequest,
    NotificationDispatchResponse,
)

router = APIRouter(prefix="/admin", tags=["Administration & PRA"])


@router.get("/users", summary="Liste des utilisateurs et rôles RBAC", dependencies=[Depends(require_roles(ROLES_ADMIN))])
def get_users(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Retourne tous les comptes utilisateurs."""
    return AdminService.list_users(db)


@router.post("/users", summary="Création d'un compte utilisateur")
def create_new_user(
    user_in: CreateUserRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLES_ADMIN)),
) -> dict[str, Any]:
    """Crée un compte utilisateur avec hachage bcrypt."""
    check_password_policy(user_in.mot_de_passe)
    try:
        return AdminService.create_user(
            db,
            identifiant=user_in.identifiant,
            email=user_in.email,
            nom_complet=user_in.nom_complet,
            mot_de_passe=user_in.mot_de_passe,
            role=user_in.role,
            current_admin_user=current_user.identifiant,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/users/{user_id}/reset-code", summary="Génère un code de réinitialisation à usage unique")
def generate_reset_code(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLES_ADMIN)),
) -> dict[str, Any]:
    """Renvoie une seule fois un code (XXXXX-XXXXX) à transmettre à l'utilisateur, qui choisit lui-même
    son nouveau mot de passe depuis « Mot de passe oublié ». Le code expire et ne sert qu'une fois."""
    from backend.app.core import reinitialisation
    from backend.app.core.config import settings
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
    if not target.est_actif:
        raise HTTPException(status_code=409, detail="Ce compte est désactivé.")
    code = reinitialisation.creer_jeton(db, target, "admin")
    log_audit_action(
        db=db, action="PASSWORD_RESET_CODE_ISSUED", cible=f"Compte: {target.identifiant}", user=current_user,
        details="Code de réinitialisation à usage unique généré par un administrateur",
        ip_address=request.client.host if request.client else "127.0.0.1",
    )
    return {"identifiant": target.identifiant, "code": code, "expire_dans_minutes": settings.RESET_TOKEN_MINUTES}


@router.post("/users/{user_id}/password", summary="Réinitialise le mot de passe d'un compte")
def reset_user_password(
    user_id: int,
    payload: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLES_ADMIN)),
) -> dict[str, Any]:
    """Définit un nouveau mot de passe et lève le verrouillage du compte."""
    check_password_policy(payload.nouveau_mot_de_passe)
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
    target.hash_mot_de_passe = get_password_hash(payload.nouveau_mot_de_passe)
    target.tentatives_echouees = 0
    target.bloque_jusqu_a = None
    db.commit()
    log_audit_action(
        db=db,
        action="PASSWORD_RESET",
        cible=f"Compte: {target.identifiant}",
        user=current_user,
        details="Mot de passe réinitialisé par un administrateur",
        ip_address=request.client.host if request.client else "127.0.0.1",
    )
    return {"id": target.id, "identifiant": target.identifiant, "reset": True}


@router.put("/users/{user_id}/status", summary="Activation/désactivation de compte")
def toggle_user_status(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLES_ADMIN)),
) -> dict[str, Any]:
    """Active ou désactive un compte utilisateur."""
    try:
        return AdminService.toggle_user_status(db, user_id=user_id, current_admin_user=current_user.identifiant)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.put("/users/{user_id}/role", summary="Modification du rôle d'un compte")
def update_user_role(
    user_id: int,
    payload: UpdateUserRoleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLES_ADMIN)),
) -> dict[str, Any]:
    """Change le rôle RBAC d'un compte (jamais le sien, jamais le dernier administrateur actif)."""
    try:
        return AdminService.update_user_role(
            db, user_id=user_id, role=payload.role, current_admin_user=current_user.identifiant
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/audit-logs", summary="Journal d'audit inaltérable", dependencies=[Depends(require_roles(ROLES_ADMIN))])
def get_audit_trail(
    limit: int = Query(default=100, ge=1, le=500),
    action: str | None = Query(default=None),
    search: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """Consulte le journal d'audit inaltérable."""
    return AdminService.get_audit_logs(db, limit=limit, action=action, search=search)


@router.post("/pra/backup", summary="Exécution d'une sauvegarde PRA à chaud")
def trigger_backup(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLES_ADMIN)),
) -> dict[str, Any]:
    """Déclenche une sauvegarde SQLite atomique avec empreinte SHA-256."""
    try:
        return AdminService.trigger_pra_backup(db, triggered_by=current_user.identifiant)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur de sauvegarde PRA : {exc}") from exc


@router.get("/pra/backups", summary="Historique des sauvegardes et conformité SHA-256", dependencies=[Depends(require_roles(ROLES_ADMIN))])
def list_backups() -> list[dict[str, Any]]:
    """Liste toutes les sauvegardes PRA disponibles."""
    return AdminService.list_pra_backups()


@router.post("/pra/verify/{filename}", summary="Vérification d'intégrité cryptographique SHA-256", dependencies=[Depends(require_roles(ROLES_ADMIN))])
def verify_backup(filename: str) -> dict[str, Any]:
    """Vérifie l'empreinte SHA-256 d'un fichier de sauvegarde."""
    try:
        return AdminService.verify_backup_integrity(filename)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/pra/restore/{filename}", summary="Restauration à chaud d'une sauvegarde PRA")
def restore_backup(
    filename: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLES_ADMIN)),
) -> dict[str, Any]:
    """
    Rôle : Restaure une sauvegarde SQLite après vérification cryptographique SHA-256.
    Entrées : filename, db.
    Sorties : Statut de restauration PRA.
    Cas d'erreur : 404 si fichier introuvable, 400 si empreinte SHA-256 invalide.
    """
    try:
        return AdminService.restore_pra_backup(db, filename=filename, triggered_by=current_user.identifiant)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur de restauration PRA : {exc}") from exc


@router.get("/pra/metrics", summary="Indicateurs de continuité RTO et RPO", dependencies=[Depends(require_roles(ROLES_ADMIN))])
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


@router.post("/users/{user_id}/mfa/reset", summary="Réinitialise le second facteur d'un compte")
def reset_user_mfa(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLES_ADMIN)),
) -> dict[str, Any]:
    """Désactive le MFA d'un utilisateur ayant perdu son appareil ; il pourra se ré-enrôler après connexion."""
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    mfa.deactivate(target)
    db.commit()
    log_audit_action(
        db=db, action="MFA_RESET", cible=f"Compte: {target.identifiant}",
        user=current_user, details="Second facteur réinitialisé par un administrateur",
    )
    return {"identifiant": target.identifiant, "mfa_active": False}


@router.get("/ssh/known-hosts", summary="Clés d'hôte SSH épinglées", dependencies=[Depends(require_roles(ROLES_ADMIN))])
def list_ssh_known_hosts() -> list[dict[str, Any]]:
    """Liste les hôtes dont la clé SSH est épinglée (empreinte SHA-256, jamais la clé complète)."""
    return ssh_trust.list_known_hosts()


@router.delete("/ssh/known-hosts/{host}", summary="Oublier la clé d'hôte SSH d'un équipement")
def forget_ssh_known_host(
    host: str,
    port: int = Query(22, ge=1, le=65535),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLES_ADMIN)),
) -> dict[str, Any]:
    """À utiliser uniquement après un remplacement légitime de l'équipement : la prochaine connexion
    ré-épinglera la nouvelle clé (ou sera refusée en mode SSH_STRICT_HOST_KEYS)."""
    removed = ssh_trust.forget_host(host, port)
    if not removed:
        raise HTTPException(status_code=404, detail="Aucune clé enregistrée pour cet hôte")
    log_audit_action(
        db=db, action="SSH_HOSTKEY_FORGET", cible=ssh_trust.host_key_name(host, port),
        user=current_user, details=f"{removed} clé(s) d'hôte SSH oubliée(s)",
    )
    return {"hote": ssh_trust.host_key_name(host, port), "cles_supprimees": removed}


@router.get("/notifications/config", summary="Lecture de la configuration persistante des notifications", dependencies=[Depends(require_roles(ROLES_ADMIN))])
def get_notification_config() -> dict[str, Any]:
    """Retourne la configuration persistée des canaux Telegram, Discord et SMTP."""
    return AdminService.get_notification_settings()


@router.put("/notifications/config", summary="Sauvegarde de la configuration des notifications")
def save_notification_config(
    payload: NotificationSettingsPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLES_ADMIN)),
) -> dict[str, Any]:
    """Sauvegarde et chiffre la configuration des canaux d'alerte sur le serveur."""
    return AdminService.save_notification_settings(db, payload.model_dump(), triggered_by=current_user.identifiant)


@router.post("/notifications/test", response_model=NotificationTestResponse, summary="Test d'un canal de notification")
def test_notification_channel(
    req: NotificationTestRequest,
    current_user: User = Depends(require_roles(ROLES_OPERATEURS)),
) -> NotificationTestResponse:
    """Effectue un test d'envoi réel sur Telegram, Discord ou SMTP.
    Un secret laissé vide par l'interface (déjà enregistré, jamais renvoyé par l'API) est repris du stockage chiffré."""
    stored = AdminService.get_notification_settings(include_secrets=True)
    if req.channel == "discord":
        if not req.discord_config:
            raise HTTPException(status_code=400, detail="Configuration Discord manquante")
        if not req.discord_config.webhook_url:
            req.discord_config.webhook_url = stored.get("discord_webhook", "")
        if not req.discord_config.webhook_url:
            raise HTTPException(status_code=400, detail="Aucun webhook Discord enregistré ni fourni")
        return NotificationService.test_discord(req.discord_config, req.message)
    elif req.channel == "telegram":
        if not req.telegram_config:
            raise HTTPException(status_code=400, detail="Configuration Telegram manquante")
        if not req.telegram_config.bot_token:
            req.telegram_config.bot_token = stored.get("telegram_token", "")
        if not req.telegram_config.bot_token:
            raise HTTPException(status_code=400, detail="Aucun jeton Telegram enregistré ni fourni")
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
    current_user: User = Depends(require_roles(ROLES_OPERATEURS)),
) -> NotificationDispatchResponse:
    """Diffuse une alerte vers l'ensemble des canaux sélectionnés et consigne au journal d'audit."""
    return NotificationService.dispatch_alert(req, db=db, current_user=current_user)

