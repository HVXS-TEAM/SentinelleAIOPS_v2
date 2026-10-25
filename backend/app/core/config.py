"""Configuration centrale de l'application Sentinelle AIOps."""
from pydantic_settings import BaseSettings
from pydantic import Field
import os
from pathlib import Path

# Répertoire de base du projet
BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseSettings):
    PROJECT_NAME: str = "Sentinelle AIOps"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Sécurité & JWT
    SECRET_KEY: str = Field(
        default="sentinelle-aiops-super-secret-key-change-in-production-2026",
        description="Clé secrète de signature des jetons JWT"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12  # 12 heures pour confort soutenance
    
    # Chiffrement Fernet pour identifiants équipements (généré ou injecté)
    # Clé Fernet 32 octets encodée en base64url par défaut pour le lab
    FERNET_KEY: str = Field(
        default="U2VudGluZWxsZUFJT3BzRmVybmV0S2V5MjAyNkxhYm9yYXRvaXJlISE=",
        description="Clé Fernet pour le chiffrement réversible des identifiants stockés"
    )

    # Base de données (SQLite par défaut, compatible PostgreSQL)
    DATABASE_URL: str = Field(
        default=f"sqlite:///{BASE_DIR}/sentinelle.db",
        description="URL de connexion SQLAlchemy (SQLite par défaut pour zéro friction)"
    )

    # Protection contre le brute-force sur la plateforme elle-même
    MAX_LOGIN_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    # Détection et Supervision : Seuils nominaux par défaut
    DEFAULT_CRITICAL_DISK_THRESHOLD: float = 90.0
    DEFAULT_WARNING_DISK_THRESHOLD: float = 80.0
    DEFAULT_TTF_ALERT_HOURS: float = 48.0

    model_config = {
        "env_file": f"{BASE_DIR}/.env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }

settings = Settings()
