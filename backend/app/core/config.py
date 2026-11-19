"""Configuration centrale de l'application Sentinelle AIOps."""
from pydantic_settings import BaseSettings
from pydantic import Field, model_validator
from cryptography.fernet import Fernet
from typing import Callable
import json
import os
import secrets
import sys
from pathlib import Path


import logging
logger = logging.getLogger("sentinelle.core.config")


def _resolve_default_directories() -> tuple[Path, Path, Path, Path]:
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
        except Exception as exc:
            logger.debug("_resolve_default_directories : repli après erreur : %s", exc)
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


def _data_dir_override() -> str:
    """Valeur de la variable d'environnement SENTINELLE_DATA_DIR ('' si absente)."""
    return os.environ.get("SENTINELLE_DATA_DIR", "").strip()


def _resolve_directories() -> tuple[Path, Path, Path, Path]:
    """
    Applique la variable d'environnement SENTINELLE_DATA_DIR (facultative) aux répertoires par défaut.
    Quand elle est définie, TOUTES les données modifiables vivent dans ce dossier : base SQLite,
    sauvegardes PRA (backup/), sauvegardes de configuration (data/config_backups/), secrets générés
    et configuration des notifications. Usage : déploiement hors du dépôt, et isolation des tests.
    """
    base_dir, bundle_dir, data_dir, db_file = _resolve_default_directories()
    override = _data_dir_override()
    if override:
        data_dir = Path(override).expanduser().resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        db_file = data_dir / "sentinelle.db"
        if getattr(sys, "frozen", False):
            base_dir = data_dir
    return base_dir, bundle_dir, data_dir, db_file


BASE_DIR, BUNDLE_DIR, DATA_DIR, DB_FILE_PATH = _resolve_directories()
BACKUP_DIR = DATA_DIR / "backup"
CONFIG_BACKUP_DIR = (
    (DATA_DIR / "data" / "config_backups")
    if (getattr(sys, "frozen", False) or _data_dir_override())
    else (BASE_DIR / "data" / "config_backups")
)
CIS_RULES_PATH = BUNDLE_DIR / "backend" / "config" / "cis_rules.yaml"

# Fichier local (hors dépôt, ignoré par git) qui conserve les secrets générés au premier démarrage.
SECRETS_FILE = DATA_DIR / ".sentinelle_secrets.json"

# Clés d'hôte SSH des équipements (format OpenSSH known_hosts), épinglées au premier contact.
SSH_KNOWN_HOSTS_FILE = DATA_DIR / "ssh_known_hosts"

# Anciennes valeurs par défaut PUBLIQUES du dépôt : refusées comme clés actives.
# Conservées uniquement pour déchiffrer d'anciennes données (voir core/security.py).
LEGACY_SECRET_KEY = "sentinelle-aiops-super-secret-key-change-in-production-2026"
LEGACY_FERNET_KEY = "U2VudGluZWxsZUFJT3BzRmVybmV0S2V5MjAyNkxhYm9yYXRvaXJlISE="


def _persisted_secret(name: str, generator: Callable[[], str], must_persist: bool = False) -> str:
    """
    Retourne un secret aléatoire fort, généré une seule fois puis conservé dans SECRETS_FILE.
    Priorité : variable d'environnement / .env (gérée par pydantic) > fichier local > génération.
    must_persist=True : lève RuntimeError si le secret ne peut pas être écrit sur disque
    (indispensable pour la clé Fernet, sinon les secrets chiffrés deviendraient illisibles au redémarrage).
    """
    data: dict = {}
    try:
        if SECRETS_FILE.exists():
            loaded = json.loads(SECRETS_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
    except (OSError, ValueError):
        data = {}

    if data.get(name):
        return str(data[name])

    value = generator()
    data[name] = value
    try:
        SECRETS_FILE.write_text(json.dumps(data), encoding="utf-8")
        try:
            os.chmod(SECRETS_FILE, 0o600)
        except OSError:
            pass
    except OSError as exc:
        if must_persist:
            raise RuntimeError(
                f"Impossible d'enregistrer {name} dans {SECRETS_FILE} ({exc}). "
                f"Définissez la variable d'environnement {name} (fichier backend/.env)."
            ) from exc
    return value


class Settings(BaseSettings):
    PROJECT_NAME: str = "Sentinelle AIOps"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"

    # Sécurité & JWT
    SECRET_KEY: str = Field(
        default_factory=lambda: _persisted_secret("SECRET_KEY", lambda: secrets.token_urlsafe(64)),
        description="Clé secrète de signature des jetons JWT (aléatoire, générée au 1er démarrage ou fournie via .env)"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # durée de vie d'une session : 8 heures

    # Chiffrement Fernet pour identifiants équipements (généré au 1er démarrage ou fourni via .env)
    FERNET_KEY: str = Field(
        default_factory=lambda: _persisted_secret(
            "FERNET_KEY", lambda: Fernet.generate_key().decode(), must_persist=True
        ),
        description="Clé Fernet pour le chiffrement réversible des identifiants stockés"
    )

    # Origines autorisées par CORS (le front de production est servi par FastAPI : même origine)
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Base de données (SQLite par défaut, compatible PostgreSQL)
    DATABASE_URL: str = Field(
        default=f"sqlite:///{DB_FILE_PATH.as_posix()}",
        description="URL de connexion SQLAlchemy (SQLite par défaut pour zéro friction)"
    )

    # Protection contre le brute-force sur la plateforme elle-même
    MAX_LOGIN_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    # Auto-inscription publique : les comptes créés sont toujours "Visiteur". Fermée par défaut :
    # les comptes sont créés par l'administrateur. Mettre à True pour ouvrir l'inscription.
    ALLOW_SELF_REGISTRATION: bool = False

    # Création de compte depuis la machine qui héberge Sentinelle (adresse de bouclage, sans
    # en-tête de proxy) : la personne qui dispose de l'application installée est de confiance et
    # choisit le profil du compte (Administrateur, Technicien ou Visiteur). Mettre à False pour
    # exiger un administrateur connecté même en local.
    LOCAL_ACCOUNT_CREATION: bool = True

    # Réinitialisation de mot de passe par e-mail. Sans SMTP_HOST et SMTP_FROM, aucun e-mail n'est
    # envoyé : l'administrateur génère alors un code à usage unique (écran Administration).
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    SMTP_STARTTLS: bool = True
    PUBLIC_URL: str = "http://127.0.0.1:8000"   # base des liens envoyés par e-mail
    RESET_TOKEN_MINUTES: int = 30

    # Vérification des clés d'hôte SSH. Par défaut : confiance au premier contact (TOFU), puis
    # épinglage : une clé qui change est TOUJOURS refusée. True = refuse aussi tout hôte inconnu
    # (les clés doivent alors être enregistrées au préalable dans le fichier ssh_known_hosts).
    SSH_STRICT_HOST_KEYS: bool = False

    # Détection d'intrusion : récepteur syslog UDP pour les équipements réseau (désactivé par défaut).
    # Le port 514 exige des droits élevés : 5514 par défaut. Seuls les équipements du parc sont écoutés.
    SYSLOG_ENABLED: bool = False
    SYSLOG_BIND: str = "0.0.0.0"
    SYSLOG_PORT: int = 5514
    # Analyse périodique du journal d'authentification (minutes) ; fenêtre analysée (minutes).
    SECURITY_SCAN_INTERVAL_MINUTES: int = 5
    SECURITY_WINDOW_MINUTES: int = 60
    # Nombre minimal d'observations historiques (IP x heure) pour entraîner l'Isolation Forest ;
    # en dessous, seules les règles statiques sont utilisées (et le rapport l'indique).
    SECURITY_MIN_BASELINE_SAMPLES: int = 30

    # Niveau de journalisation (DEBUG, INFO, WARNING, ERROR, CRITICAL). Fichier : <données>/logs/sentinelle.log
    LOG_LEVEL: str = "INFO"

    # Détection et Supervision : Seuils nominaux par défaut
    DEFAULT_CRITICAL_DISK_THRESHOLD: float = 90.0
    DEFAULT_WARNING_DISK_THRESHOLD: float = 80.0
    DEFAULT_TTF_ALERT_HOURS: float = 48.0

    @model_validator(mode="after")
    def _refuse_insecure_keys(self) -> "Settings":
        """Refuse de démarrer avec une clé publique, trop courte ou invalide."""
        if self.SECRET_KEY == LEGACY_SECRET_KEY or len(self.SECRET_KEY) < 32:
            raise ValueError("SECRET_KEY invalide : valeur publique ou inférieure à 32 caractères.")
        if self.FERNET_KEY == LEGACY_FERNET_KEY:
            raise ValueError("FERNET_KEY invalide : valeur publique historique du dépôt.")
        try:
            Fernet(self.FERNET_KEY.encode())
        except Exception as exc:
            raise ValueError("FERNET_KEY invalide : clé Fernet attendue (32 octets en base64 url-safe).") from exc
        self.LOG_LEVEL = self.LOG_LEVEL.upper()
        if self.LOG_LEVEL not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("LOG_LEVEL invalide : DEBUG, INFO, WARNING, ERROR ou CRITICAL attendu.")
        return self

    model_config = {
        "env_file": f"{BASE_DIR.as_posix()}/.env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


settings = Settings()
