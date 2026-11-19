"""Collecte et analyse syntaxique des événements d'authentification RÉELS.

Sources : /var/log/auth.log ou /var/log/secure, journald (sshd), journal Windows « Security »
(événements 4625 et 4624) et lignes syslog des équipements réseau (Cisco IOS, sshd distant).
Aucune ligne n'est jamais fabriquée : si une source est illisible, le statut le dit.
"""
from __future__ import annotations

import ipaddress
import logging
import platform
import re
import subprocess
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinelle.securite.collectors")

MAX_LIGNES_JOURNAL = 5000
_MOIS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

_SSH_ECHEC = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam|none) for (invalid user )?(\S+) from (\S+) port \d+"
)
_SSH_SUCCES = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam|hostbased) for (\S+) from (\S+) port \d+"
)
_CISCO = re.compile(
    r"%SEC_LOGIN-\d-LOGIN_(FAILED|SUCCESS)\b.*?\[user: ?([^\]]*)\].*?\[Source: ?([^\]]+)\]"
)
_TS_SYSLOG = re.compile(r"(?<![\w])([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
_TS_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?")


def _ip_valide(valeur: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(valeur.strip("[]")))
    except ValueError:
        return None


def _vers_utc_naif(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.astimezone()  # heure locale de l'hôte
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def extraire_horodatage(ligne: str, defaut: Optional[datetime] = None, maintenant: Optional[datetime] = None) -> datetime:
    """Horodatage UTC naïf d'une ligne ; `defaut` (ou maintenant) si la ligne n'en porte pas."""
    maintenant = maintenant or datetime.now(timezone.utc).replace(tzinfo=None)
    m = _TS_ISO.search(ligne[:60])
    if m:
        a, mo, j, h, mi, s, tz = m.groups()
        try:
            dt = datetime(int(a), int(mo), int(j), int(h), int(mi), int(s))
            if tz:
                signe = 0 if tz == "Z" else (1 if tz[0] == "+" else -1)
                dec = 0 if tz == "Z" else int(tz[1:3]) * 60 + int(tz[-2:])
                return dt - timedelta(minutes=signe * dec)
            return _vers_utc_naif(dt)
        except ValueError:
            pass
    m = _TS_SYSLOG.search(ligne[:60])
    if m and m.group(1) in _MOIS:
        mois, jour, h, mi, s = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
        local_now = datetime.now()
        try:
            dt = datetime(local_now.year, _MOIS[mois], jour, h, mi, s)
            if dt > local_now + timedelta(days=1):  # journal de fin d'année relu en janvier
                dt = dt.replace(year=dt.year - 1)
            return _vers_utc_naif(dt)
        except ValueError:
            pass
    return defaut if defaut is not None else maintenant


def parse_auth_line(
    ligne: str,
    origine: str = "syslog",
    defaut: Optional[datetime] = None,
) -> Optional[Dict[str, Any]]:
    """Analyse une ligne sshd ou Cisco IOS. Renvoie None si ce n'est pas un événement d'authentification."""
    m = _SSH_ECHEC.search(ligne)
    if m:
        ip = _ip_valide(m.group(3))
        if ip:
            return {"horodatage": extraire_horodatage(ligne, defaut), "ip": ip, "user": m.group(2),
                    "succes": False, "invalide": bool(m.group(1)), "origine": origine}
    m = _SSH_SUCCES.search(ligne)
    if m:
        ip = _ip_valide(m.group(2))
        if ip:
            return {"horodatage": extraire_horodatage(ligne, defaut), "ip": ip, "user": m.group(1),
                    "succes": True, "invalide": False, "origine": origine}
    m = _CISCO.search(ligne)
    if m:
        ip = _ip_valide(m.group(3))
        if ip:
            return {"horodatage": extraire_horodatage(ligne, defaut), "ip": ip, "user": m.group(2).strip() or None,
                    "succes": m.group(1) == "SUCCESS", "invalide": False, "origine": origine}
    return None


def parse_windows_events_xml(xml_texte: str) -> List[Dict[str, Any]]:
    """Événements 4625 (échec) et 4624 (succès réseau/bureau à distance) issus de `wevtutil ... /f:xml`."""
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    try:
        racine = ET.fromstring(f"<Events>{xml_texte}</Events>")
    except ET.ParseError:
        return []
    evenements: List[Dict[str, Any]] = []
    for ev in racine.iter(f"{ns}Event"):
        eid = (ev.findtext(f"{ns}System/{ns}EventID") or "").strip()
        if eid not in ("4625", "4624"):
            continue
        donnees = {d.get("Name"): (d.text or "").strip() for d in ev.iter(f"{ns}Data")}
        ip = _ip_valide(donnees.get("IpAddress", "")) if donnees.get("IpAddress", "-") not in ("", "-") else None
        if not ip:
            continue  # connexion locale ou service : aucune source distante à attribuer
        if eid == "4624" and donnees.get("LogonType") not in ("3", "10"):
            continue
        tc = ev.find(f"{ns}System/{ns}TimeCreated")
        brut = (tc.get("SystemTime") if tc is not None else "") or ""
        try:
            brut = re.sub(r"(\.\d{6})\d+", r"\1", brut).replace("Z", "+00:00")
            horo = datetime.fromisoformat(brut).astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            continue
        evenements.append({
            "horodatage": horo, "ip": ip, "user": donnees.get("TargetUserName") or None,
            "succes": eid == "4624",
            "invalide": eid == "4625" and donnees.get("SubStatus", "").lower() == "0xc0000064",
            "origine": "windows_eventlog",
        })
    return evenements


def _statut(source: str, lisible: bool, detail: str, n: int = 0) -> Dict[str, Any]:
    return {"source": source, "lisible": lisible, "detail": detail, "evenements_lus": n}


def _lire_fichier(chemin: str) -> List[str]:
    with open(chemin, "r", encoding="utf-8", errors="ignore") as f:
        return list(deque(f, maxlen=MAX_LIGNES_JOURNAL))


def collecter_linux() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    statuts: List[Dict[str, Any]] = []
    for chemin in ("/var/log/auth.log", "/var/log/secure"):
        try:
            lignes = _lire_fichier(chemin)
        except FileNotFoundError:
            continue
        except OSError as exc:
            statuts.append(_statut(chemin, False, f"illisible : {exc.strerror or exc}"))
            continue
        evs = [e for e in (parse_auth_line(l, origine="linux_authlog") for l in lignes) if e]
        statuts.append(_statut(chemin, True, "lu", len(evs)))
        return evs, statuts
    try:
        res = subprocess.run(
            ["journalctl", "_COMM=sshd", "_COMM=sshd-session", "--since", "-24h", "-o", "short-iso", "--no-pager", "-q"],
            capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL,
        )
        if res.returncode == 0:
            lignes = res.stdout.splitlines()[-MAX_LIGNES_JOURNAL:]
            evs = [e for e in (parse_auth_line(l, origine="journald") for l in lignes) if e]
            statuts.append(_statut("journald", True, "lu", len(evs)))
            return evs, statuts
        statuts.append(_statut("journald", False, (res.stderr or "échec de journalctl").strip()[:200]))
    except FileNotFoundError:
        statuts.append(_statut("journald", False, "journalctl absent"))
    except Exception as exc:  # pragma: no cover - dépend de l'hôte
        logger.warning("Lecture de journald en échec : %s", exc)
        statuts.append(_statut("journald", False, str(exc)[:200]))
    return [], statuts


def collecter_windows() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    no_win = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        res = subprocess.run(
            ["wevtutil", "qe", "Security", "/q:*[System[(EventID=4625 or EventID=4624)]]",
             f"/c:{MAX_LIGNES_JOURNAL // 5}", "/rd:true", "/f:xml"],
            capture_output=True, timeout=20, stdin=subprocess.DEVNULL, creationflags=no_win,
        )
    except Exception as exc:
        logger.warning("Lecture du journal Windows Security en échec : %s", exc)
        return [], [_statut("Windows Security", False, str(exc)[:200])]
    if res.returncode != 0:
        msg = res.stderr.decode("cp850", errors="ignore").strip()[:200] or "accès refusé (droits administrateur requis)"
        return [], [_statut("Windows Security", False, msg)]
    evs = parse_windows_events_xml(res.stdout.decode("utf-8", errors="ignore"))
    return evs, [_statut("Windows Security", True, "lu", len(evs))]


def collecter_hote() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Événements d'authentification de la machine qui héberge Sentinelle + statut de chaque source."""
    if platform.system() == "Windows":
        return collecter_windows()
    return collecter_linux()
