"""Service de cybersécurité : détection d'intrusion sur journaux d'authentification RÉELS.

Chaîne de traitement :
1. Collecte (collectors.py) : journal de l'hôte (auth.log, journald, EventLog Windows) et syslog des
   équipements réseau (syslog_receiver.py). Les événements sont enregistrés dans `journal_authentifications`.
2. Agrégation par adresse IP source sur une fenêtre glissante.
3. Détection : règles statiques (force brute, password spraying) TOUJOURS actives ; Isolation Forest
   entraîné sur l'historique réel (IP x fenêtre) dès que `SECURITY_MIN_BASELINE_SAMPLES` observations
   sont disponibles. Le rapport indique le modèle réellement utilisé.
4. Réponse : alertes dédupliquées, blocage pare-feu réellement appliqué (sinon refus explicite).
"""
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
import hashlib
import ipaddress
import platform
import re
import shutil
import socket
import subprocess
import numpy as np
try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.models import (
    EvenementSecurite, Alerte, Equipement, JournalAuthentification, User,
)
from backend.app.core.audit import log_audit_action
from backend.app.modules.securite import collectors


import logging
logger = logging.getLogger("sentinelle.securite.service")

# Règles statiques (toujours actives)
BRUTE_FORCE_MIN_ECHECS = 5
BRUTE_FORCE_MIN_RATIO = 0.8
SPRAYING_MIN_COMPTES = 3
SPRAYING_MIN_ECHECS = 3
SEUIL_CRITIQUE_ECHECS = 20


def _maintenant() -> datetime:
    """UTC naïf : format des horodatages stockés en base."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def anonymize_ip_rgpd(ip_address: str) -> str:
    """
    Rôle : Masque le dernier octet de l'adresse IPv4 conformément aux préconisations RGPD/CNIL.
    Entrées : Adresse IP (ip_address).
    Sorties : Adresse IP anonymisée (ex: 198.51.100.***).
    """
    clean_ip = ip_address.split(" ")[0].strip()
    if clean_ip.endswith(".***") or clean_ip.endswith(".x"):
        return clean_ip
    parts = clean_ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.***"
    return "IP.ANONYME"


def _hidden_startupinfo():
    """Masque toute fenêtre console sous Windows."""
    if platform.system() == "Windows" and hasattr(subprocess, "STARTUPINFO"):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 1)
        si.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
        return si
    return None


class SecurityService:
    @staticmethod
    def parse_log_line(log_line: str) -> Optional[Dict[str, Any]]:
        """
        Rôle : Analyse une ligne d'authentification sshd ou Cisco IOS (%SEC_LOGIN).
        Entrées : Ligne de log brute.
        Sorties : {user, ip, type, is_failed, is_invalid_user} ou None.
        """
        ev = collectors.parse_auth_line(log_line)
        if not ev:
            return None
        return {
            "user": ev["user"],
            "ip": ev["ip"],
            "type": "auth_success" if ev["succes"] else "auth_failed",
            "is_failed": 0 if ev["succes"] else 1,
            "is_invalid_user": 1 if ev["invalide"] else 0,
        }

    @staticmethod
    def extract_features(events: List[Dict[str, Any]]) -> np.ndarray:
        """
        Rôle : Matrice de caractéristiques de l'Isolation Forest, une ligne par (IP, fenêtre) :
               [0] nombre d'événements, [1] taux d'échec, [2] compte inexistant ciblé (0/1),
               [3] échecs par minute.
        """
        return np.array([
            [float(e["count"]), float(e["fail_ratio"]), float(e["invalid_user_flag"]), float(e["attempts_per_min"])]
            for e in events
        ])

    # ── Journal d'authentification ───────────────────────────────────────────

    @staticmethod
    def ingest_events(db: Session, events: List[Dict[str, Any]], equipement_id: Optional[int] = None) -> int:
        """Enregistre les événements non encore vus (dédoublonnage par empreinte). Renvoie le nombre ajouté."""
        if not events:
            return 0
        compteur: Dict[str, int] = {}
        lignes: Dict[str, Dict[str, Any]] = {}
        for ev in events:
            base = f"{ev['horodatage'].isoformat()}|{ev['ip']}|{ev.get('user')}|{int(ev['succes'])}|{ev['origine']}"
            n = compteur.get(base, 0)
            compteur[base] = n + 1
            lignes[hashlib.sha256(f"{base}|{n}".encode()).hexdigest()] = ev
        existantes = set()
        cles = list(lignes)
        for i in range(0, len(cles), 500):
            lot = cles[i:i + 500]
            existantes.update(
                r[0] for r in db.query(JournalAuthentification.empreinte)
                .filter(JournalAuthentification.empreinte.in_(lot)).all()
            )
        ajoutes = 0
        for emp, ev in lignes.items():
            if emp in existantes:
                continue
            db.add(JournalAuthentification(
                empreinte=emp, horodatage=ev["horodatage"], source_ip=ev["ip"],
                utilisateur=(ev.get("user") or None) and str(ev["user"])[:80],
                succes=bool(ev["succes"]), utilisateur_invalide=bool(ev.get("invalide")),
                origine=ev["origine"], equipement_id=ev.get("equipement_id", equipement_id),
            ))
            ajoutes += 1
        db.commit()
        return ajoutes

    @staticmethod
    def _agreger(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Agrège des événements {ip, user, succes, invalide, horodatage} par IP source."""
        par_ip: Dict[str, Dict[str, Any]] = {}
        for ev in events:
            s = par_ip.setdefault(ev["ip"], {
                "ip": ev["ip"], "count": 0, "fails": 0, "invalid": 0, "users": set(),
                "first": ev["horodatage"], "last": ev["horodatage"], "equipements": {},
            })
            s["count"] += 1
            s["fails"] += 0 if ev["succes"] else 1
            s["invalid"] += 1 if ev.get("invalide") else 0
            if ev.get("user"):
                s["users"].add(ev["user"])
            s["first"] = min(s["first"], ev["horodatage"])
            s["last"] = max(s["last"], ev["horodatage"])
            if ev.get("equipement_id"):
                s["equipements"][ev["equipement_id"]] = s["equipements"].get(ev["equipement_id"], 0) + 1
        resultat = []
        for s in par_ip.values():
            minutes = max(1.0, (s["last"] - s["first"]).total_seconds() / 60.0)
            resultat.append({
                "ip": s["ip"], "count": s["count"], "fails": s["fails"],
                "fail_ratio": s["fails"] / s["count"],
                "invalid_user_flag": 1.0 if s["invalid"] else 0.0,
                "attempts_per_min": s["fails"] / minutes,
                "target_users": sorted(s["users"]),
                "equipement_id": max(s["equipements"], key=s["equipements"].get) if s["equipements"] else None,
            })
        return resultat

    @staticmethod
    def _matrice_reference(db: Session, avant: datetime, fenetre_min: int) -> np.ndarray:
        """Historique réel (IP x fenêtre) antérieur à la fenêtre courante : base d'apprentissage."""
        rows = db.query(JournalAuthentification).filter(JournalAuthentification.horodatage < avant).all()
        seaux: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
        for r in rows:
            cle = (r.source_ip, int(r.horodatage.replace(tzinfo=timezone.utc).timestamp() // (fenetre_min * 60)))
            seaux.setdefault(cle, []).append({
                "ip": r.source_ip, "user": r.utilisateur, "succes": r.succes,
                "invalide": r.utilisateur_invalide, "horodatage": r.horodatage,
            })
        lignes = []
        for evs in seaux.values():
            lignes.extend(SecurityService._agreger(evs))
        return SecurityService.extract_features(lignes) if lignes else np.empty((0, 4))

    @staticmethod
    def _detecter(agg: List[Dict[str, Any]], reference: np.ndarray) -> Tuple[str, List[Dict[str, Any]]]:
        """Applique règles statiques + Isolation Forest (si historique suffisant). Renvoie (modèle, verdicts)."""
        modele = "regles_statiques"
        if_pred = [1] * len(agg)
        if_score = [0.0] * len(agg)
        if agg and len(reference) >= settings.SECURITY_MIN_BASELINE_SAMPLES:
            forest = IsolationForest(n_estimators=200, contamination="auto", random_state=42).fit(reference)
            X = SecurityService.extract_features(agg)
            if_pred = list(forest.predict(X))
            if_score = [float(round(-s, 3)) for s in forest.decision_function(X)]
            modele = "isolation_forest+regles_statiques"
        verdicts = []
        for i, it in enumerate(agg):
            brute = it["fails"] >= BRUTE_FORCE_MIN_ECHECS and it["fail_ratio"] >= BRUTE_FORCE_MIN_RATIO
            spraying = len(it["target_users"]) >= SPRAYING_MIN_COMPTES and it["fails"] >= SPRAYING_MIN_ECHECS
            ecart = if_pred[i] == -1 and it["fails"] > 0
            verdicts.append({
                "brute_force": brute, "spraying": spraying, "ecart_if": ecart,
                "score": if_score[i] if modele != "regles_statiques" else 0.0,
                "anomalie": brute or spraying or ecart,
            })
        return modele, verdicts

    @staticmethod
    def _rapport_item(it: Dict[str, Any], v: Dict[str, Any]) -> Dict[str, Any]:
        type_ev = (
            "brute_force" if v["brute_force"] else "password_spraying" if v["spraying"]
            else "ecart_comportemental" if v["ecart_if"] else "echecs_authentification"
        )
        severite = "INFO"
        if v["anomalie"]:
            severite = "CRITICAL" if (it["fails"] >= SEUIL_CRITIQUE_ECHECS or v["spraying"]) else "WARNING"
        elif it["fails"] > 0:
            severite = "INFO"
        methodes = [m for m, ok in (("règle force brute", v["brute_force"]), ("règle spraying", v["spraying"]),
                                    ("Isolation Forest", v["ecart_if"])) if ok]
        explication = (
            f"{it['count']} événement(s) d'authentification dont {it['fails']} échec(s), "
            f"{it['attempts_per_min']:.1f} échec/min, comptes visés : {', '.join(it['target_users']) or 'inconnu'}."
            + (f" Détecté par : {', '.join(methodes)}." if methodes else "")
        )
        return {"type": type_ev, "severite": severite, "explication": explication}

    @classmethod
    def analyze_window(cls, db: Session, window_minutes: Optional[int] = None,
                       maintenant: Optional[datetime] = None) -> Dict[str, Any]:
        """Analyse le journal réel sur la fenêtre courante, enregistre les événements et alertes (dédupliqués)."""
        fenetre = window_minutes or settings.SECURITY_WINDOW_MINUTES
        maintenant = maintenant or _maintenant()
        debut = maintenant - timedelta(minutes=fenetre)
        rows = db.query(JournalAuthentification).filter(JournalAuthentification.horodatage >= debut).all()
        evs = [{"ip": r.source_ip, "user": r.utilisateur, "succes": r.succes, "invalide": r.utilisateur_invalide,
                "horodatage": r.horodatage, "equipement_id": r.equipement_id} for r in rows]
        agg = cls._agreger(evs)
        reference = cls._matrice_reference(db, debut, fenetre)
        modele, verdicts = cls._detecter(agg, reference)

        anomalies = []
        for it, v in zip(agg, verdicts):
            if it["fails"] == 0:
                continue
            info = cls._rapport_item(it, v)
            ip_anon = anonymize_ip_rgpd(it["ip"])
            existant = (
                db.query(EvenementSecurite)
                .filter(EvenementSecurite.source_ip == it["ip"], EvenementSecurite.horodatage >= debut)
                .order_by(EvenementSecurite.horodatage.desc()).first()
            )
            champs = dict(
                equipement_id=it["equipement_id"], utilisateur_cible=",".join(it["target_users"])[:50],
                type_evenement=info["type"], score_anomalie=v["score"], severite=info["severite"],
                is_anomaly=v["anomalie"], explication=info["explication"],
                tentatives_minute=int(round(it["attempts_per_min"])),
            )
            if existant:
                bloque = "[BLOQUÉ]" in (existant.explication or "")
                for k, val in champs.items():
                    setattr(existant, k, val)
                if bloque:
                    existant.explication = f"[BLOQUÉ] {existant.explication}"
            else:
                db.add(EvenementSecurite(source_ip=it["ip"], source_ip_anonymisee=ip_anon,
                                         horodatage=maintenant, **champs))
            if v["anomalie"]:
                titre = f"Cyberattaque détectée : {info['type']} ({ip_anon})"
                deja = db.query(Alerte).filter(Alerte.titre == titre, Alerte.statut == "Active").first()
                if not deja:
                    db.add(Alerte(equipement_id=it["equipement_id"], module_origine="Sécurité",
                                  severite=info["severite"], titre=titre, message=info["explication"],
                                  statut="Active", date_creation=datetime.now(timezone.utc)))
                anomalies.append({"ip": ip_anon, "type": info["type"], "severite": info["severite"],
                                  "score_ia": v["score"], "explication": info["explication"],
                                  "detecte_par_regle": v["brute_force"] or v["spraying"],
                                  "detecte_par_isolation_forest": v["ecart_if"]})
        db.commit()
        return {
            "fenetre_minutes": fenetre,
            "evenements_analyses": len(rows),
            "ip_evaluees": len(agg),
            "modele": modele,
            "echantillons_baseline": int(len(reference)),
            "anomalies_detectees": len(anomalies),
            "anomalies": anomalies,
        }

    @classmethod
    def run_real_security_scan(cls, db: Session, audit: bool = True) -> Dict[str, Any]:
        """
        Rôle : Lit les journaux d'authentification de l'hôte, les enregistre, puis analyse la fenêtre courante.
        Sorties : Rapport (sources lues avec leur statut, modèle utilisé, anomalies) + statistiques de sockets.
        """
        host_eq = db.query(Equipement).filter(Equipement.nom == socket.gethostname()).first()
        evs, sources = collectors.collecter_hote()
        nouveaux = cls.ingest_events(db, evs, equipement_id=host_eq.id if host_eq else None)
        rapport = cls.analyze_window(db)

        actives = ecoute = 0
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == "LISTEN":
                    ecoute += 1
                elif c.raddr:
                    actives += 1
        except Exception as exc:
            logger.debug("run_real_security_scan : sockets illisibles : %s", exc)

        if audit or rapport["anomalies_detectees"]:
            log_audit_action(
                db=db, action="SECURITY_REAL_SCAN", cible=socket.gethostname(),
                details=(f"{nouveaux} nouvel(s) événement(s) d'authentification, "
                         f"{rapport['evenements_analyses']} analysé(s), {rapport['anomalies_detectees']} anomalie(s) "
                         f"(modèle : {rapport['modele']})."),
            )
        return {
            **rapport,
            "sources": sources,
            "nouveaux_evenements": nouveaux,
            "aucune_source_lisible": not any(s["lisible"] for s in sources),
            "active_connections_count": actives,
            "listening_ports_count": ecoute,
        }

    @classmethod
    def train_and_detect_anomalies(cls, db: Session, log_batch: List[str],
                                   equipement_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Rôle : Analyse un lot de lignes fourni par l'opérateur. ANALYSE SEULE : rien n'est enregistré
               (ni journal, ni événement, ni alerte), car ces lignes ne sont pas des observations de l'hôte.
        """
        now = _maintenant()
        evs = []
        for line in log_batch:
            e = collectors.parse_auth_line(line, defaut=now)
            if e:
                evs.append({"ip": e["ip"], "user": e["user"], "succes": e["succes"],
                            "invalide": e["invalide"], "horodatage": e["horodatage"]})
        agg = cls._agreger(evs)
        reference = cls._matrice_reference(db, now, settings.SECURITY_WINDOW_MINUTES)
        modele, verdicts = cls._detecter(agg, reference)
        anomalies = []
        for it, v in zip(agg, verdicts):
            if v["anomalie"]:
                info = cls._rapport_item(it, v)
                anomalies.append({"ip": anonymize_ip_rgpd(it["ip"]), "type": info["type"],
                                  "severite": info["severite"], "score_ia": v["score"],
                                  "explication": info["explication"]})
        return {
            "total_logs": len(log_batch),
            "lignes_reconnues": len(evs),
            "ip_evaluees": len(agg),
            "modele": modele,
            "echantillons_baseline": int(len(reference)),
            "anomalies_detectees": len(anomalies),
            "anomalies": anomalies,
            "persiste": False,
        }

    @staticmethod
    def _apply_firewall_block(clean_ip: str, rule_name: str) -> Tuple[bool, str, str]:
        """Crée réellement la règle de blocage (netsh sous Windows, iptables sous Linux).
        Renvoie (appliqué, mode, détail) ; jamais « appliqué » sans code retour 0."""
        no_win = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            if platform.system() == "Windows":
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}",
                       "dir=in", "action=block", f"remoteip={clean_ip}"]
                res = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL, timeout=5,
                                     creationflags=no_win, startupinfo=_hidden_startupinfo())
                mode = "WINDOWS_DEFENDER_FIREWALL"
            else:
                ipt = shutil.which("iptables")
                if not ipt:
                    return False, "AUCUN", "iptables est introuvable sur l'hôte."
                verif = subprocess.run([ipt, "-C", "INPUT", "-s", clean_ip, "-j", "DROP"],
                                       capture_output=True, stdin=subprocess.DEVNULL, timeout=5)
                if verif.returncode == 0:
                    return True, "IPTABLES", "Règle déjà présente."
                res = subprocess.run([ipt, "-I", "INPUT", "-s", clean_ip, "-j", "DROP"],
                                     capture_output=True, stdin=subprocess.DEVNULL, timeout=5)
                mode = "IPTABLES"
        except Exception as exc:
            logger.warning("Blocage d'adresse IP au pare-feu en échec : %s", exc)
            return False, "AUCUN", str(exc)[:200]
        if res.returncode == 0:
            return True, mode, "Règle créée."
        err = (res.stderr or res.stdout or b"").decode("utf-8", errors="ignore").strip()
        return False, mode, err[:200] or "droits administrateur requis"

    @staticmethod
    def block_ip_address(
        db: Session,
        source_ip: str,
        incident_id: Optional[int] = None,
        equipement_id: Optional[int] = None,
        motif: str = "Blocage Pare-feu SOC",
        user: Optional[User] = None,
    ) -> Dict[str, Any]:
        """
        Rôle : Bloque une adresse IP au pare-feu de l'hôte. Le blocage n'est déclaré (et l'incident
               n'est marqué « BLOQUÉ ») que si la règle a réellement été créée.
        Sorties : status BLOCKED, ou NOT_APPLIED avec la raison. ValueError si l'IP n'est pas valide.
        """
        clean_ip = source_ip.split(" ")[0].strip()
        try:
            clean_ip = str(ipaddress.ip_address(clean_ip))
        except ValueError:
            raise ValueError("Adresse IP invalide : une IP complète est nécessaire (les IP anonymisées ne peuvent pas être bloquées).")
        rule_name = f"Sentinelle_Block_{clean_ip.replace('.', '_').replace(':', '_')}"

        applied, firewall_mode, detail = SecurityService._apply_firewall_block(clean_ip, rule_name)
        if not applied:
            log_audit_action(db=db, action="FIREWALL_BLOCK_FAILED", cible=clean_ip, user=user,
                             details=f"{motif} | Échec : {detail}")
            return {
                "status": "NOT_APPLIED", "source_ip": clean_ip, "rule_name": rule_name,
                "firewall_mode": firewall_mode,
                "message": f"Aucune règle de pare-feu n'a été créée pour {clean_ip} : {detail}",
            }

        ev = None
        if incident_id:
            ev = db.query(EvenementSecurite).filter(EvenementSecurite.id == incident_id).first()
        if not ev:
            ev = (
                db.query(EvenementSecurite)
                .filter(EvenementSecurite.source_ip == clean_ip)
                .order_by(EvenementSecurite.horodatage.desc())
                .first()
            )
        if ev and "[BLOQUÉ]" not in (ev.explication or ""):
            ev.explication = f"[BLOQUÉ] {ev.explication or ''} (Règle {rule_name} appliquée)".strip()

        anon = anonymize_ip_rgpd(clean_ip)
        now = datetime.now(timezone.utc)
        for al in db.query(Alerte).filter(
            Alerte.module_origine == "Sécurité", Alerte.statut == "Active", Alerte.titre.like(f"%({anon})%"),
        ).all():
            al.statut = "Résolue"
            al.date_acquittement = now
            al.acquittee_par = user.identifiant if user else "SOC-AutoBlock"
        db.commit()

        log_audit_action(db=db, action="FIREWALL_BLOCK_IP", cible=f"{clean_ip} ({rule_name})", user=user,
                         details=f"{motif} | Mode: {firewall_mode}")
        return {
            "status": "BLOCKED", "source_ip": clean_ip, "rule_name": rule_name,
            "firewall_mode": firewall_mode,
            "message": f"Règle de pare-feu '{rule_name}' créée pour {clean_ip} ({firewall_mode}).",
        }

    @staticmethod
    def isolate_device(
        db: Session,
        device_name: str,
        equipement_id: Optional[int] = None,
        motif: str = "Isolement de sécurité SOC",
        user: Optional[User] = None,
    ) -> Dict[str, Any]:
        """
        Rôle : Marque un équipement « Quarantaine SOC » dans Sentinelle (groupe, alerte, audit).
               AUCUNE action réseau n'est exécutée : l'isolement effectif (VLAN, ACL, port) reste à faire.
        Entrées : Session DB, nom de l'équipement, ID optionnel, motif, utilisateur.
        Sorties : Dictionnaire de confirmation d'isolement.
        """
        eq = None
        if equipement_id:
            eq = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if not eq and device_name:
            eq = db.query(Equipement).filter(Equipement.nom == device_name).first()

        now = datetime.now(timezone.utc)
        target_label = f"{eq.nom} ({eq.ip})" if eq else device_name

        if eq:
            eq.groupe = "Quarantaine SOC"
            alerte = Alerte(
                equipement_id=eq.id,
                module_origine="Sécurité",
                severite="WARNING",
                titre=f"Équipement marqué en quarantaine : {eq.nom}",
                message=f"L'équipement {eq.nom} ({eq.ip}) a été marqué en quarantaine dans Sentinelle ({motif}). Aucune action réseau exécutée.",
                statut="Acquittée",
                date_creation=now,
                date_acquittement=now,
                acquittee_par=user.identifiant if user else "admin",
            )
            db.add(alerte)
            db.commit()

        log_audit_action(
            db=db,
            action="DEVICE_ISOLATE",
            cible=target_label,
            user=user,
            details=f"Marquage quarantaine (sans action réseau) : {motif}",
        )

        return {
            "status": "QUARANTINE_MARKED",
            "device": target_label,
            "network_action_performed": False,
            "message": (f"{target_label} est marqué « Quarantaine SOC » dans Sentinelle. "
                        "Aucune action réseau n'a été exécutée : isolez l'équipement (VLAN, ACL, port) séparément."),
        }
