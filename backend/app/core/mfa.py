"""Second facteur TOTP (RFC 6238) : enrôlement, vérification, codes de secours.

Stockage : tout l'état MFA d'un compte (secret TOTP, codes de secours hachés, dernier pas de temps
consommé) est un petit JSON chiffré avec Fernet dans la colonne `utilisateurs.mfa_secret`.
Le secret n'est jamais renvoyé par l'API après l'enrôlement.

Protections :
  - fenêtre de tolérance d'un pas (±30 s) pour les horloges légèrement décalées ;
  - anti-rejeu : un code déjà utilisé (ou antérieur) est refusé ;
  - codes de secours à usage unique, stockés sous forme de hachés SHA-256 ;
  - les échecs comptent dans le verrouillage anti-bruteforce du compte (voir endpoints/auth.py).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Optional

import pyotp

from backend.app.core.security import decrypt_secret, encrypt_secret
from backend.app.db.models import User

import logging
logger = logging.getLogger("sentinelle.core.mfa")


ISSUER = "Sentinelle AIOps"
STEP_SECONDS = 30
RECOVERY_CODE_COUNT = 8


def _load(user: User) -> Optional[dict[str, Any]]:
    if not user.mfa_secret:
        return None
    try:
        data = json.loads(decrypt_secret(user.mfa_secret))
    except Exception as exc:
        logger.warning("État MFA illisible (déchiffrement ou JSON invalide) : %s", exc)
        return None
    return data if isinstance(data, dict) and data.get("secret") else None


def _store(user: User, data: Optional[dict[str, Any]]) -> None:
    user.mfa_secret = encrypt_secret(json.dumps(data)) if data else None


def _hash_recovery(code: str) -> str:
    normalise = code.strip().lower().replace("-", "").replace(" ", "")
    return hashlib.sha256(normalise.encode()).hexdigest()


def has_pending_enrollment(user: User) -> bool:
    return (not user.mfa_active) and _load(user) is not None


def start_enrollment(user: User) -> dict[str, str]:
    """Génère un nouveau secret (non actif tant qu'un code valide n'a pas été saisi)."""
    secret = pyotp.random_base32()
    _store(user, {"secret": secret, "recovery": [], "last_step": 0})
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=ISSUER)
    return {"secret": secret, "otpauth_uri": uri, "issuer": ISSUER}


def _matching_step(secret: str, code: str, now: float) -> Optional[int]:
    """Retourne le pas de temps correspondant au code (fenêtre ±1), ou None."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(secret, interval=STEP_SECONDS)
    base_step = int(now // STEP_SECONDS)
    for offset in (0, -1, 1):
        step = base_step + offset
        if hmac.compare_digest(totp.at(step * STEP_SECONDS), code):
            return step
    return None


def verify_totp(user: User, code: str, now: Optional[float] = None) -> bool:
    """Vérifie un code TOTP et consomme son pas de temps (anti-rejeu). Ne fait pas de commit."""
    data = _load(user)
    if not data:
        return False
    step = _matching_step(data["secret"], code, time.time() if now is None else now)
    if step is None or step <= int(data.get("last_step", 0)):
        return False
    data["last_step"] = step
    _store(user, data)
    return True


def verify_recovery_code(user: User, code: str) -> bool:
    """Vérifie et consomme un code de secours à usage unique. Ne fait pas de commit."""
    data = _load(user)
    if not data or not code:
        return False
    digest = _hash_recovery(code)
    for stored in list(data.get("recovery", [])):
        if hmac.compare_digest(stored, digest):
            data["recovery"].remove(stored)
            _store(user, data)
            return True
    return False


def verify_second_factor(user: User, code: str) -> bool:
    """Accepte un code TOTP à 6 chiffres ou un code de secours."""
    return verify_totp(user, code) or verify_recovery_code(user, code)


def activate(user: User, code: str) -> list[str]:
    """Active le MFA si `code` est valide ; retourne les codes de secours EN CLAIR (affichés une fois)."""
    data = _load(user)
    if not data:
        raise ValueError("Aucun enrôlement en cours : appelez d'abord /auth/mfa/setup.")
    if not verify_totp(user, code):
        raise ValueError("Code invalide.")
    data = _load(user)  # relecture : verify_totp a mis à jour last_step
    clear_codes = [f"{secrets.token_hex(3)}-{secrets.token_hex(2)}-{secrets.token_hex(3)}"
                   for _ in range(RECOVERY_CODE_COUNT)]
    data["recovery"] = [_hash_recovery(c) for c in clear_codes]
    _store(user, data)
    user.mfa_active = True
    return clear_codes


def deactivate(user: User) -> None:
    user.mfa_active = False
    _store(user, None)


def remaining_recovery_codes(user: User) -> int:
    data = _load(user)
    return len(data.get("recovery", [])) if data else 0

