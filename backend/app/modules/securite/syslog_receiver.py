"""Récepteur syslog UDP : alimente le journal d'authentification avec les événements des équipements réseau.

Sécurité : seuls les datagrammes émis par l'adresse IP d'un équipement du parc sont traités (les autres
sont comptés puis ignorés), ce qui empêche l'injection de faux événements par un tiers.
Configuration sur un Cisco IOS :  logging host <ip-du-serveur> transport udp port 5514
                                  login on-failure log  /  login on-success log
"""
from __future__ import annotations

import logging
import socket
import threading
from datetime import datetime, timezone
from typing import Callable, Optional

from backend.app.core.config import settings
from backend.app.db.models import Equipement
from backend.app.db.session import SessionLocal
from backend.app.modules.securite import collectors
from backend.app.modules.securite.service import SecurityService

logger = logging.getLogger("sentinelle.securite.syslog")

TAILLE_MAX_DATAGRAMME = 4096


class SyslogReceiver:
    def __init__(self, host: str, port: int, session_factory: Callable = SessionLocal):
        self.host = host
        self._port = port
        self._session_factory = session_factory
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.recus = 0
        self.ignores_source_inconnue = 0
        self.enregistres = 0

    @property
    def port(self) -> int:
        return self._sock.getsockname()[1] if self._sock else self._port

    def handle(self, data: bytes, adresse: str) -> bool:
        """Traite un datagramme ; renvoie True si un événement d'authentification a été enregistré."""
        try:
            return self._traiter(data, adresse)
        finally:
            self.recus += 1  # compté en dernier : un lecteur qui attend `recus` voit les autres compteurs à jour

    def _traiter(self, data: bytes, adresse: str) -> bool:
        texte = data[:TAILLE_MAX_DATAGRAMME].decode("utf-8", errors="replace")
        with self._session_factory() as db:
            eq = db.query(Equipement).filter(Equipement.ip == adresse).first()
            if not eq:
                self.ignores_source_inconnue += 1
                return False
            maintenant = datetime.now(timezone.utc).replace(tzinfo=None)
            ev = collectors.parse_auth_line(texte, origine="syslog", defaut=maintenant)
            if not ev:
                return False
            ev["equipement_id"] = eq.id
            ajoutes = SecurityService.ingest_events(db, [ev])
            self.enregistres += ajoutes
            return ajoutes > 0

    def _boucle(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(TAILLE_MAX_DATAGRAMME)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.handle(data, addr[0])
            except Exception:
                logger.exception("Datagramme syslog non traité")

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.host, self._port))
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._boucle, name="syslog-receiver", daemon=True)
        self._thread.start()
        logger.info("Récepteur syslog à l'écoute sur %s:%s (UDP)", self.host, self.port)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._sock:
            self._sock.close()
            self._sock = None


_instance: Optional[SyslogReceiver] = None


def get_receiver() -> Optional[SyslogReceiver]:
    return _instance


def start_syslog_receiver() -> Optional[SyslogReceiver]:
    """Démarre le récepteur si SYSLOG_ENABLED ; une erreur de liaison est journalisée sans bloquer le serveur."""
    global _instance
    if not settings.SYSLOG_ENABLED or _instance is not None:
        return _instance
    try:
        rec = SyslogReceiver(settings.SYSLOG_BIND, settings.SYSLOG_PORT)
        rec.start()
        _instance = rec
    except OSError as exc:
        logger.error("Récepteur syslog non démarré (%s:%s) : %s", settings.SYSLOG_BIND, settings.SYSLOG_PORT, exc)
    return _instance
