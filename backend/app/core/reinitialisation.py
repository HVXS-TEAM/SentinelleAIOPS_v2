"""Jetons à usage unique de réinitialisation de mot de passe.

Seule l'empreinte SHA-256 est stockée. Un jeton expire (RESET_TOKEN_MINUTES), ne sert qu'une fois,
et se bloque après 5 essais erronés. Deux formes : lien e-mail (jeton long) et code remis par
l'administrateur (XXXXX-XXXXX, sans caractères ambigus).
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.models import JetonReinitialisation, User

MAX_ESSAIS = 5
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def _maintenant() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _empreinte(valeur: str) -> str:
    return hashlib.sha256(valeur.encode("utf-8")).hexdigest()


def _formes(code: str) -> set[str]:
    """Empreintes candidates : valeur brute (jeton e-mail) et code normalisé (saisie humaine)."""
    brut = code.strip()
    normalise = brut.replace("-", "").replace(" ", "").upper()
    return {_empreinte(brut), _empreinte(normalise)}


def creer_jeton(db: Session, user: User, origine: str) -> str:
    """Invalide les jetons en cours de l'utilisateur, en crée un nouveau et renvoie sa valeur en clair."""
    maintenant = _maintenant()
    for ancien in db.query(JetonReinitialisation).filter(
        JetonReinitialisation.utilisateur_id == user.id, JetonReinitialisation.utilise_le.is_(None)
    ):
        ancien.utilise_le = maintenant
    if origine == "admin":
        brut = "".join(secrets.choice(_ALPHABET) for _ in range(10))
        clair, a_hacher = f"{brut[:5]}-{brut[5:]}", brut
    else:
        clair = a_hacher = secrets.token_urlsafe(32)
    db.add(JetonReinitialisation(
        utilisateur_id=user.id, empreinte=_empreinte(a_hacher), origine=origine,
        expire_le=maintenant + timedelta(minutes=settings.RESET_TOKEN_MINUTES),
    ))
    db.commit()
    return clair


def demande_recente(db: Session, user: User, secondes: int = 60) -> bool:
    """Vrai si un jeton e-mail a été créé il y a moins de `secondes` (anti-spam)."""
    limite = _maintenant() - timedelta(seconds=secondes)
    return db.query(JetonReinitialisation).filter(
        JetonReinitialisation.utilisateur_id == user.id,
        JetonReinitialisation.origine == "email",
        JetonReinitialisation.date_creation > limite,
    ).first() is not None


def consommer(db: Session, user: User, code: str) -> bool:
    """Vérifie le code et le marque utilisé. Un échec compte un essai sur les jetons actifs."""
    maintenant = _maintenant()
    actifs = db.query(JetonReinitialisation).filter(
        JetonReinitialisation.utilisateur_id == user.id,
        JetonReinitialisation.utilise_le.is_(None),
        JetonReinitialisation.expire_le > maintenant,
        JetonReinitialisation.tentatives < MAX_ESSAIS,
    ).all()
    candidats = _formes(code)
    for jeton in actifs:
        if any(hmac.compare_digest(jeton.empreinte, c) for c in candidats):
            jeton.utilise_le = maintenant
            db.commit()
            return True
    for jeton in actifs:
        jeton.tentatives += 1
    db.commit()
    return False
