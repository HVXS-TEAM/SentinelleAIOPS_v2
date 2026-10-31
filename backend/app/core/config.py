"""Configuration centrale de l'application Sentinelle AIOps."""
from pydantic_settings import BaseSettings
from pydantic import Field
import os
import sys
from pathlib import Path


def _resolve_directories() -> tuple[Path, Path, Path, Path]:
    """
    Résout proprement les répertoires selon le mode d'exécution :
    - Mode compilé PyInstaller (sys.frozen = True) :
      * BUNDLE_DIR : dossier d'extraction PyInstaller (_MEIPASS) contenant les assets en lecture seule
      * DATA_DIR   : dossier persistant à côté de l'exécutable (ou %LOCALAPPDATA%\\Sentinelle AIOps)
      * DB_FILE    : DATA_DIR / "sentinelle.db" (persistance garantie entre les redémarrages)
    - Mode développement / tests (sys.frozen = False) :
      * PROJECT_ROOT : racine du dépôt
      * BASE_DIR     : dossier backend/
      * DB_FILE      : backend/sentinelle.db
    """
    if getattr(sys, "frozen", False):
        bundle_dir = Path(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))).resolve()
        exec_dir = Path(os.path.dirname(sys.executable)).resolve()
        # Vérifier que exec_dir est accessible en écriture
        data_dir = exec_dir
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            test_file = data_dir / ".write_test"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink(missing_ok=True)
        except Exception:
            local_app_data = os.environ.get("LOCALAPPDATA") or str(Path.home())
            data_dir = Path(local_app_data) / "Sentinelle AIOps"
            data_dir.mkdir(parents=True, exist_ok=True)
        base_dir = data_dir
        db_file = data_dir / "sentinelle.db"
        return base_dir, bundle_dir, data_dir, db_file
    else:
        base_dir = Path(__file__).resolve().parent.parent.parent  # .../backend
        project_root = base_dir.parent                             # racine du projet
        db_file = base_dir / "sentinelle.db"
        return base_dir, project_root, project_root, db_file


BASE_DIR, BUNDLE_DIR, DATA_DIR, DB_FILE_PATH = _resolve_directories()
BACKUP_DIR = DATA_DIR / "backup"
CONFIG_BACKUP_DIR = (DATA_DIR / "data" / "config_backups") if getattr(sys, "frozen", False) else (BASE_DIR / "data" / "config_backups")
CIS_RULES_PATH = BUNDLE_DIR / "backend" / "config" / "cis_rules.yaml"


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
        default=f"sqlite:///{DB_FILE_PATH.as_posix()}",
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
        "env_file": f"{BASE_DIR.as_posix()}/.env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


settings = Settings()
