"""Vérification des clés d'hôte SSH : confiance au premier contact (TOFU) puis épinglage.

Remplace paramiko.AutoAddPolicy, qui acceptait n'importe quelle clé à chaque connexion
(attaque de l'homme du milieu triviale, identifiants d'équipements exposés).

Fonctionnement :
  - hôte inconnu : sa clé est enregistrée dans SSH_KNOWN_HOSTS_FILE (mode TOFU), ou la
    connexion est refusée si SSH_STRICT_HOST_KEYS=True ;
  - hôte connu avec la même clé : connexion acceptée ;
  - hôte connu avec une AUTRE clé : connexion toujours refusée (paramiko.BadHostKeyException).
    Aucun mode permissif n'existe ; l'administrateur doit oublier explicitement l'ancienne clé.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

import paramiko

from backend.app.core import config as cfg

logger = logging.getLogger("sentinelle.ssh")
_LOCK = threading.Lock()


class UnknownHostKeyError(paramiko.SSHException):
    """Hôte inconnu refusé car SSH_STRICT_HOST_KEYS est activé."""


def known_hosts_path() -> Path:
    return Path(cfg.SSH_KNOWN_HOSTS_FILE)


def host_key_name(host: str, port: int = 22) -> str:
    """Nom utilisé par paramiko/OpenSSH : 'hôte' pour le port 22, '[hôte]:port' sinon."""
    return host if port == 22 else f"[{host}]:{port}"


def _load() -> paramiko.HostKeys:
    keys = paramiko.HostKeys()
    path = known_hosts_path()
    if path.exists():
        keys.load(str(path))
    return keys


def _save(keys: paramiko.HostKeys) -> None:
    path = known_hosts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    keys.save(str(path))
    try:
        path.chmod(0o600)
    except OSError:
        pass


class _PinnedPolicy(paramiko.MissingHostKeyPolicy):
    """Politique appliquée aux hôtes absents du fichier known_hosts."""

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        from backend.app.core.config import settings

        if settings.SSH_STRICT_HOST_KEYS:
            logger.error("Clé d'hôte SSH inconnue refusée (mode strict) : %s", hostname)
            raise UnknownHostKeyError(
                f"Clé d'hôte inconnue pour {hostname} et SSH_STRICT_HOST_KEYS est activé."
            )
        with _LOCK:
            keys = _load()
            keys.add(hostname, key.get_name(), key)
            _save(keys)
        client.get_host_keys().add(hostname, key.get_name(), key)
        logger.warning(
            "Première connexion SSH à %s : clé %s %s enregistrée (TOFU).",
            hostname, key.get_name(), fingerprint(key),
        )


def fingerprint(key: paramiko.PKey) -> str:
    """Empreinte SHA-256 au format OpenSSH (SHA256:...)."""
    import base64
    import hashlib

    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def new_ssh_client() -> paramiko.SSHClient:
    """Client Paramiko qui vérifie les clés d'hôte (jamais d'AutoAddPolicy)."""
    client = paramiko.SSHClient()
    with _LOCK:
        keys = _load()
    for hostname, entry in keys.items():
        for key_type, key in entry.items():
            client.get_host_keys().add(hostname, key_type, key)
    client.set_missing_host_key_policy(_PinnedPolicy())
    return client


def is_host_key_error(exc: BaseException) -> bool:
    return isinstance(exc, (paramiko.BadHostKeyException, UnknownHostKeyError))


def log_connection_failure(host: str, exc: BaseException) -> None:
    """Journalise un échec de connexion SSH ; une clé modifiée est tracée comme alerte de sécurité."""
    if isinstance(exc, paramiko.BadHostKeyException):
        logger.critical(
            "ALERTE SÉCURITÉ : la clé d'hôte SSH de %s a CHANGÉ (équipement remplacé ou interception). "
            "Connexion refusée.", host,
        )
    elif isinstance(exc, UnknownHostKeyError):
        logger.error("Connexion SSH refusée vers %s : %s", host, exc)
    else:
        logger.info("Connexion SSH impossible vers %s : %s", host, exc)


def list_known_hosts() -> list[dict[str, Any]]:
    with _LOCK:
        keys = _load()
    rows: list[dict[str, Any]] = []
    for hostname, entry in keys.items():
        for key_type, key in entry.items():
            rows.append({"hote": hostname, "type": key_type, "empreinte": fingerprint(key)})
    return sorted(rows, key=lambda r: (r["hote"], r["type"]))


def forget_host(host: str, port: int = 22) -> int:
    """Supprime les clés enregistrées pour un hôte ; retourne le nombre de clés oubliées."""
    name = host_key_name(host, port)
    removed = 0
    with _LOCK:
        keys = _load()
        while True:
            try:
                del keys[name]
            except KeyError:
                break
            removed += 1
        if removed:
            _save(keys)
    return removed

