"""Service de journalisation inaltérable d'audit (Audit Trail).

Garantit la traçabilité intégrale de toutes les opérations sensibles :
authentification, modification de seuils, application de scripts réseau, simulation.
"""
from typing import Optional
from sqlalchemy.orm import Session
from backend.app.db.models import JournalAudit, User


def log_audit_action(
    db: Session,
    action: str,
    cible: str,
    user: Optional[User] = None,
    details: Optional[str] = None,
    ip_address: Optional[str] = "127.0.0.1",
) -> JournalAudit:
    """Enregistre un événement critique dans le journal d'audit."""
    entry = JournalAudit(
        utilisateur_id=user.id if user else None,
        nom_utilisateur=user.identifiant if user else "Système",
        action=action,
        cible=cible,
        details=details,
        adresse_ip=ip_address,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
