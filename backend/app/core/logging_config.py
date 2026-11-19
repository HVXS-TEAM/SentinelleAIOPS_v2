"""Journalisation applicative : console + fichier rotatif.

Tous les loggers de l'application s'appellent « sentinelle.* ». Le fichier de log vit dans
DATA_DIR/logs/sentinelle.log (5 Mo x 5 fichiers). Ne jamais journaliser de secret (mot de passe,
jeton, URL de webhook) : les messages ne contiennent que des noms d'objets et des types d'erreur.
"""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from backend.app.core import config as cfg

LOGGER_NAME = "sentinelle"
LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s : %(message)s"
_MARK = "_sentinelle_handler"


def log_file_path() -> Path:
    return Path(cfg.DATA_DIR) / "logs" / "sentinelle.log"


def setup_logging(level: str | None = None) -> logging.Logger:
    """Configure le logger « sentinelle » (idempotent : n'ajoute jamais deux fois les gestionnaires)."""
    from backend.app.core.config import settings

    root = logging.getLogger(LOGGER_NAME)
    root.setLevel(getattr(logging, (level or settings.LOG_LEVEL).upper(), logging.INFO))

    for h in list(root.handlers):
        if getattr(h, _MARK, False):
            root.removeHandler(h)
            h.close()

    formatter = logging.Formatter(LOG_FORMAT)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    setattr(console, _MARK, True)
    root.addHandler(console)

    try:
        path = log_file_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fichier = logging.handlers.RotatingFileHandler(
            path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        fichier.setFormatter(formatter)
        setattr(fichier, _MARK, True)
        root.addHandler(fichier)
    except OSError as exc:
        root.warning("Fichier de log indisponible (%s) : journalisation console uniquement.", exc)
    return root

