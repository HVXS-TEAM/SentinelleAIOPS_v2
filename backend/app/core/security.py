"""Fonctions de sécurité, hachage, chiffrement et gestion des jetons JWT."""
from datetime import datetime, timedelta, timezone
from typing import Optional, Any, Union
from jose import jwt
import bcrypt
from cryptography.fernet import Fernet, MultiFernet
import base64
from backend.app.core.config import settings, LEGACY_FERNET_KEY


import logging
logger = logging.getLogger("sentinelle.core.security")


def _legacy_fernet() -> Fernet:
    """Ancienne clé publique du dépôt : sert UNIQUEMENT à déchiffrer d'anciennes données."""
    raw_key = LEGACY_FERNET_KEY.encode()
    try:
        return Fernet(raw_key)
    except Exception as exc:
        logger.debug("_legacy_fernet : repli après erreur : %s", exc)
        return Fernet(base64.urlsafe_b64encode(raw_key.ljust(32, b"0")[:32]))


def _get_fernet() -> MultiFernet:
    """Chiffre avec la clé active ; déchiffre avec la clé active puis l'ancienne clé (migration)."""
    return MultiFernet([Fernet(settings.FERNET_KEY.encode()), _legacy_fernet()])


fernet_cipher = _get_fernet()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie la concordance entre mot de passe en clair et hash bcrypt."""
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception as exc:
        logger.warning("Vérification du mot de passe impossible (hachage invalide) : %s", exc)
        return False


def get_password_hash(password: str) -> str:
    """Génère un hash bcrypt sécurisé pour le mot de passe."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def create_access_token(subject: Union[str, Any], role: str, expires_delta: Optional[timedelta] = None) -> str:
    """Génère un jeton d'accès JWT signé avec sujet, rôle et date d'expiration."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "exp": expire,
        "sub": str(subject),
        "role": role,
        "iat": datetime.now(timezone.utc),
    }
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def encrypt_secret(plain_secret: str) -> str:
    """Chiffre un secret (ex: identifiants SSH/SNMP) via Fernet (AES-128-CBC)."""
    if not plain_secret:
        return ""
    return fernet_cipher.encrypt(plain_secret.encode()).decode()


def decrypt_secret(encrypted_secret: str) -> str:
    """Déchiffre un secret chiffré au repos pour connexion réseau légitime."""
    if not encrypted_secret:
        return ""
    try:
        return fernet_cipher.decrypt(encrypted_secret.encode()).decode()
    except Exception as e:
        raise ValueError(f"Impossible de déchiffrer le secret : {str(e)}")
