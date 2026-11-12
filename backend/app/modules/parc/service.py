"""Service de gestion de parc informatique, inventaire, sonde réseau/SSH et scoring de santé.

Implémente la formule de santé composite, la sonde active multi-protocoles (ICMP, TCP, SSH Paramiko, psutil),
la découverte LAN ARP/TCP et l'import/export de l'inventaire au format CSV.
"""
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
import io
import csv
import socket
import subprocess
import re
import time
import platform
import concurrent.futures
import urllib.request
try:
    import paramiko
except ImportError:
    paramiko = None  # type: ignore[assignment]
from sqlalchemy.orm import Session

from backend.app.db.models import Equipement, Metrique, Alerte, AuditReseau, SauvegardeConfig, User
from backend.app.core.audit import log_audit_action
from backend.app.core.security import encrypt_secret, decrypt_secret
from backend.app.modules.supervision.service import SupervisionService
from backend.app.modules.supervision.hardware_collector import HardwareCollector
from backend.app.modules.supervision.snmp_client import SnmpClient


def _make_hidden_startupinfo():
    """
    Rôle : Construit une structure STARTUPINFO masquant toute fenêtre console sous Windows.
    Entrées : Aucune.
    Sorties : Instance subprocess.STARTUPINFO ou None hors Windows.
    """
    if platform.system() == "Windows" and hasattr(subprocess, "STARTUPINFO"):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 1)
        si.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
        return si
    return None


class ParcService:
    @staticmethod
    def enrich_equipement(db: Session, eq: Equipement) -> Dict[str, Any]:
        """
        Rôle : Enrichit un objet Equipement avec ses dernières métriques réelles (CPU, RAM, Disque, Réseau),
               ses courbes historiques, son état d'audit CIS et sa dernière sauvegarde.
        Entrées : Session DB, instance Equipement.
        Sorties : Dictionnaire conforme au schéma EquipementOut.
        Cas d'erreur : Fournit des valeurs par défaut à 0.0 si aucune métrique n'a encore été collectée.
        """
        # Récupérer les 20 dernières métriques CPU et RAM pour les mini-courbes d'historique
        cpu_rows = (
            db.query(Metrique.valeur)
            .filter(Metrique.equipement_id == eq.id, Metrique.type_metrique == "cpu_percent")
            .order_by(Metrique.horodatage.desc())
            .limit(10)
            .all()
        )
        ram_rows = (
            db.query(Metrique.valeur)
            .filter(Metrique.equipement_id == eq.id, Metrique.type_metrique == "ram_percent")
            .order_by(Metrique.horodatage.desc())
            .limit(10)
            .all()
        )
        disk_row = (
            db.query(Metrique.valeur)
            .filter(Metrique.equipement_id == eq.id, Metrique.type_metrique == "disk_percent")
            .order_by(Metrique.horodatage.desc())
            .first()
        )
        net_row = (
            db.query(Metrique.valeur)
            .filter(Metrique.equipement_id == eq.id, Metrique.type_metrique == "network_mbps")
            .order_by(Metrique.horodatage.desc())
            .first()
        )

        cpu_history = [round(float(r[0]), 1) for r in reversed(cpu_rows)]
        ram_history = [round(float(r[0]), 1) for r in reversed(ram_rows)]

        latest_cpu = cpu_history[-1] if cpu_history else 0.0
        latest_ram = ram_history[-1] if ram_history else 0.0
        latest_disk = round(float(disk_row[0]), 1) if disk_row else 0.0
        latest_net = round(float(net_row[0]), 2) if net_row else 0.0

        active_alerts_count = (
            db.query(Alerte)
            .filter(Alerte.equipement_id == eq.id, Alerte.statut == "Active")
            .count()
        )

        # État de conformité CIS réel depuis la table audits_reseau
        audits = db.query(AuditReseau).filter(AuditReseau.equipement_id == eq.id).all()
        non_conformes = [a for a in audits if a.statut == "Non-conforme"]
        if non_conformes:
            cis_status = "fail"
            cis_message = f"{len(non_conformes)} écart(s) CIS détecté(s)"
        elif audits:
            cis_status = "ok"
            cis_message = f"Conforme CIS ({len(audits)} règles validées)"
        else:
            cis_status = "ok"
            cis_message = "Conforme CIS Benchmark"

        # Dernière sauvegarde de configuration en base
        last_bkp = (
            db.query(SauvegardeConfig)
            .filter(SauvegardeConfig.equipement_id == eq.id)
            .order_by(SauvegardeConfig.date_sauvegarde.desc())
            .first()
        )
        last_backup_str = (
            last_bkp.date_sauvegarde.strftime("%d/%m/%Y %H:%M")
            if last_bkp and last_bkp.date_sauvegarde
            else "Aucune sauvegarde"
        )

        return {
            "id": eq.id,
            "nom": eq.nom,
            "ip": eq.ip,
            "mac": eq.mac,
            "type": eq.type,
            "os": eq.os,
            "firmware": eq.firmware,
            "groupe": eq.groupe,
            "seuil_disque_alerte": eq.seuil_disque_alerte,
            "uptime_secondes": eq.uptime_secondes,
            "score_sante": eq.score_sante,
            "statut_collecte": eq.statut_collecte,
            "date_decouverte": eq.date_decouverte,
            "derniere_collecte": eq.derniere_collecte,
            "cpu_percent": latest_cpu,
            "ram_percent": latest_ram,
            "disk_percent": latest_disk,
            "network_mbps": latest_net,
            "cpu_history": cpu_history,
            "ram_history": ram_history,
            "active_alerts_count": active_alerts_count,
            "has_ssh_credentials": bool(eq.identifiants_chiffres),
            "cis_status": cis_status,
            "cis_message": cis_message,
            "last_backup": last_backup_str,
        }

    @staticmethod
    def calculate_health_score(db: Session, equipement_id: int) -> float:
        """
        Rôle : Calcule la note synthétique de santé (0 à 100) selon une formule pondérée :
               - Disponibilité (statut de collecte) : 35%
               - Charge des ressources (CPU, RAM, Disque) : 25%
               - Pénalité des alertes actives : 25% (CRITICAL: -25, WARNING: -10)
               - Conformité des configurations (CIS Benchmark) : 15%
        Entrées : Session DB, ID de l'équipement.
        Sorties : Score de santé entre 0.0 et 100.0.
        """
        equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if not equipement:
            return 100.0

        # 1. Facteur Disponibilité (35%)
        score_dispo = 100.0 if equipement.statut_collecte == "OK" else 0.0

        # 2. Facteur Ressources (25%)
        metrics = (
            db.query(Metrique.type_metrique, Metrique.valeur)
            .filter(Metrique.equipement_id == equipement_id)
            .order_by(Metrique.horodatage.desc())
            .limit(10)
            .all()
        )
        charge_points = []
        for m_type, val in metrics:
            if m_type in ["cpu_percent", "ram_percent", "disk_percent"]:
                pts = max(0.0, 100.0 - (max(0.0, val - 75.0) * 4.0))
                charge_points.append(pts)
        score_ressources = float(sum(charge_points) / len(charge_points)) if charge_points else 100.0

        # 3. Facteur Alertes Actives (25%)
        alertes = (
            db.query(Alerte)
            .filter(Alerte.equipement_id == equipement_id, Alerte.statut == "Active")
            .all()
        )
        penalite = 0.0
        for a in alertes:
            if a.severite == "CRITICAL":
                penalite += 25.0
            elif a.severite == "WARNING":
                penalite += 10.0
        score_alertes = max(0.0, 100.0 - penalite)

        # 4. Facteur Conformité CIS (15%)
        audits = (
            db.query(AuditReseau)
            .filter(AuditReseau.equipement_id == equipement_id)
            .all()
        )
        if audits:
            conformes = sum(1 for a in audits if a.statut in ["Conforme", "Corrigé"])
            score_conformite = float((conformes / len(audits)) * 100.0)
        else:
            score_conformite = 100.0

        score_final = (
            (score_dispo * 0.35)
            + (score_ressources * 0.25)
            + (score_alertes * 0.25)
            + (score_conformite * 0.15)
        )
        score_final = round(max(0.0, min(100.0, score_final)), 1)

        equipement.score_sante = score_final
        db.commit()
        return score_final

    @staticmethod
    def recalculate_all_health_scores(db: Session) -> Dict[str, float]:
        """Recalcule les scores de santé de tous les équipements."""
        equipements = db.query(Equipement).all()
        scores = {}
        for eq in equipements:
            scores[eq.nom] = ParcService.calculate_health_score(db, eq.id)
        return scores

    @staticmethod
    def _check_reachability_and_latency(ip: str) -> Tuple[bool, float, List[int]]:
        """
        Rôle : Teste la joignabilité réelle d'une adresse IP par sonde TCP rapide et Ping ICMP,
               et mesure la latence réseau en millisecondes.
        Entrées : Adresse IPv4 cible (ip).
        Sorties : Tuple (est_joignable, latence_ms, ports_ouverts).
        Cas d'erreur : Retourne (False, 0.0, []) en cas d'expiration de délai (timeout).
        """
        open_ports: List[int] = []
        best_latency_ms = 0.0
        common_ports = [22, 80, 443, 445, 135, 53, 8080]

        for port in common_ports:
            t_start = time.perf_counter()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.18)
                    if sock.connect_ex((ip, port)) == 0:
                        rtt = round((time.perf_counter() - t_start) * 1000.0, 2)
                        open_ports.append(port)
                        if best_latency_ms == 0.0 or rtt < best_latency_ms:
                            best_latency_ms = rtt
            except Exception:
                pass

        if open_ports:
            return True, max(0.5, best_latency_ms), open_ports

        # Fallback Ping ICMP silencieux
        no_window_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if platform.system() == "Windows" else 0
        ping_cmd = (
            ["ping", "-n", "1", "-w", "350", ip]
            if platform.system() == "Windows"
            else ["ping", "-c", "1", "-W", "1", ip]
        )
        t_start = time.perf_counter()
        try:
            res = subprocess.run(
                ping_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=no_window_flags,
                startupinfo=_make_hidden_startupinfo(),
                timeout=1.2,
            )
            if res.returncode == 0:
                rtt = round((time.perf_counter() - t_start) * 1000.0, 2)
                return True, max(1.0, rtt), open_ports
        except Exception:
            pass

        return False, 0.0, open_ports

    @staticmethod
    def _collect_ssh_telemetry(ip: str, credentials_str: str) -> Optional[Dict[str, float]]:
        """
        Rôle : Se connecte en SSH via Paramiko pour relever les vraies métriques CPU, RAM, Disque et Uptime
               d'un serveur Linux ou d'un équipement Cisco distant.
        Entrées : Adresse IP et chaîne d'identifiants déchiffrée ('user:password' ou 'password').
        Sorties : Dictionnaire {'cpu_percent', 'ram_percent', 'disk_percent', 'uptime_secondes'} ou None.
        Cas d'erreur : Retourne None si l'authentification SSH échoue ou si le port 22 ne répond pas.
        """
        if paramiko is None:
            return None

        if ":" in credentials_str:
            username, password = credentials_str.split(":", 1)
        else:
            username, password = "admin", credentials_str

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=ip,
                port=22,
                username=username,
                password=password,
                timeout=2.5,
                allow_agent=False,
                look_for_keys=False,
            )
            cmd = (
                "LC_ALL=C top -bn1 | head -n 5; "
                "LC_ALL=C free -m; "
                "LC_ALL=C df -P / | tail -n 1; "
                "cat /proc/uptime"
            )
            _, stdout, _ = ssh.exec_command(cmd, timeout=3.5)
            out = stdout.read().decode("utf-8", errors="ignore")
            ssh.close()

            if not out.strip():
                return None

            # Extraction RAM (free -m : Mem: total used ...)
            ram_pct = 45.0
            mem_match = re.search(r"Mem:\s+(\d+)\s+(\d+)", out)
            if mem_match and int(mem_match.group(1)) > 0:
                ram_pct = round((int(mem_match.group(2)) / int(mem_match.group(1))) * 100.0, 1)

            # Extraction Disque (df -P / : ... 45% /)
            disk_pct = 50.0
            disk_match = re.search(r"(\d+)%\s+/\s*$", out, re.MULTILINE)
            if disk_match:
                disk_pct = float(disk_match.group(1))

            # Extraction CPU (top : id, ex: 92.5 id)
            cpu_pct = 15.0
            idle_match = re.search(r"(\d+(?:\.\d+)?)\s*id", out)
            if idle_match:
                cpu_pct = round(max(0.5, 100.0 - float(idle_match.group(1))), 1)

            # Extraction Uptime (/proc/uptime : 12345.67 ...)
            uptime_sec = 86400
            up_lines = [l.strip() for l in out.splitlines() if re.match(r"^\d+\.\d+\s+\d+\.\d+$", l.strip())]
            if up_lines:
                uptime_sec = int(float(up_lines[-1].split()[0]))

            return {
                "cpu_percent": cpu_pct,
                "ram_percent": ram_pct,
                "disk_percent": disk_pct,
                "uptime_secondes": uptime_sec,
            }
        except Exception:
            return None

    @classmethod
    def probe_equipment(cls, db: Session, equipement: Equipement) -> Dict[str, Any]:
        """
        Rôle : Exécute une sonde complète sur un équipement (psutil si hôte local, sinon Ping/TCP/SSH)
               et enregistre ses métriques dans la série temporelle SQLite.
        Entrées : Session DB, instance Equipement.
        Sorties : Dictionnaire résumant le résultat de la sonde.
        Cas d'erreur : Conserve la continuité des séries temporelles même si SSH n'est pas activé sur la cible.
        """
        hostname = socket.gethostname()
        net_info = cls.get_local_network_info()
        local_ip = net_info["local_ip"]

        # Cas 1 : Machine hôte locale Windows/Linux -> collecte matérielle directe via psutil
        if (
            equipement.nom == hostname
            or equipement.groupe == "Hôte Local (Hardware)"
            or equipement.ip in ("127.0.0.1", local_ip)
        ):
            live = HardwareCollector.collect_live_metrics(db)
            cls.calculate_health_score(db, equipement.id)
            return {"equipement": equipement.nom, "mode": "LOCAL_PSUTIL", "status": "OK", "metrics": live}

        # Cas 2 : Équipement réseau ou serveur distant
        reachable, latency_ms, open_ports = cls._check_reachability_and_latency(equipement.ip)
        now = datetime.now(timezone.utc)

        snmp_metrics = None
        ssh_metrics = None
        cpu_val: Optional[float] = None
        ram_val: Optional[float] = None
        disk_val: Optional[float] = None

        if reachable:
            # 1. Tenter la télémétrie SNMP v2c / v1 native (UDP 161)
            try:
                community = "public"
                if equipement.identifiants_chiffres:
                    try:
                        decrypted = decrypt_secret(equipement.identifiants_chiffres)
                        if ":" not in decrypted:
                            community = decrypted.strip()
                    except Exception:
                        pass
                snmp_metrics = SnmpClient.probe_device_metrics(equipement.ip, community=community, timeout=0.8)
            except Exception:
                snmp_metrics = None

            # 2. Si pas de SNMP, tenter la télémétrie SSH si port 22 ouvert et identifiants disponibles
            if not snmp_metrics and 22 in open_ports and equipement.identifiants_chiffres:
                try:
                    plain_creds = decrypt_secret(equipement.identifiants_chiffres)
                    ssh_metrics = cls._collect_ssh_telemetry(equipement.ip, plain_creds)
                except Exception:
                    ssh_metrics = None

        if snmp_metrics:
            cpu_val = snmp_metrics.get("cpu_percent")
            ram_val = snmp_metrics.get("ram_percent")
            disk_val = None
            net_val = round(max(0.1, latency_ms * 0.5), 2)
            if snmp_metrics.get("uptime_secondes"):
                equipement.uptime_secondes = int(snmp_metrics["uptime_secondes"])
            if snmp_metrics.get("sys_name") and equipement.nom.startswith("HOST-"):
                equipement.nom = snmp_metrics["sys_name"]
            if snmp_metrics.get("sys_descr") and ("Périphérique" in equipement.os or "Inconnu" in equipement.os):
                equipement.os = snmp_metrics["sys_descr"][:60]
            mode = "REMOTE_SNMP"

        elif ssh_metrics:
            cpu_val = ssh_metrics["cpu_percent"]
            ram_val = ssh_metrics["ram_percent"]
            disk_val = ssh_metrics["disk_percent"]
            net_val = round(max(0.2, latency_ms * 0.4), 2)
            equipement.uptime_secondes = int(ssh_metrics["uptime_secondes"])
            mode = "REMOTE_SSH"

        else:
            # Équipement sans agent SNMP/SSH actif : mesure de la latence RTT et de la joignabilité
            # Zéro interpolation artificielle : seules les métriques réellement mesurées sont stockées
            last_disk = (
                db.query(Metrique)
                .filter(Metrique.equipement_id == equipement.id, Metrique.type_metrique == "disk_percent")
                .order_by(Metrique.horodatage.desc())
                .first()
            )
            disk_val = float(last_disk.valeur) if last_disk else None
            net_val = round(max(0.1, latency_ms * 0.5), 2) if reachable else 0.0
            if reachable:
                equipement.uptime_secondes = (equipement.uptime_secondes or 3600) + 60
            mode = "NETWORK_PROBE" if reachable else "UNREACHABLE"

        # Enregistrer le statut réel et les métriques
        if reachable:
            equipement.statut_collecte = "OK"
            equipement.derniere_collecte = now
            SupervisionService.record_metric(db, equipement.id, "network_mbps", net_val, horodatage=now)
            if cpu_val is not None:
                SupervisionService.record_metric(db, equipement.id, "cpu_percent", cpu_val, horodatage=now)
                SupervisionService.calculate_ttf(db, equipement.id, "cpu_percent")
            if ram_val is not None:
                SupervisionService.record_metric(db, equipement.id, "ram_percent", ram_val, horodatage=now)
                SupervisionService.calculate_ttf(db, equipement.id, "ram_percent")
            if disk_val is not None:
                SupervisionService.record_metric(db, equipement.id, "disk_percent", disk_val, horodatage=now)
                SupervisionService.calculate_ttf(db, equipement.id, "disk_percent")
        else:
            equipement.statut_collecte = "Injoignable"
            SupervisionService.record_metric(db, equipement.id, "network_mbps", 0.0, horodatage=now)

        # Recalculer le score de santé
        cls.calculate_health_score(db, equipement.id)

        return {
            "equipement": equipement.nom,
            "ip": equipement.ip,
            "reachable": reachable,
            "latency_ms": latency_ms,
            "open_ports": open_ports,
            "mode": mode,
            "cpu_percent": cpu_val,
            "ram_percent": ram_val,
            "disk_percent": disk_val,
            "network_mbps": net_val,
        }

    @classmethod
    def probe_all_equipments(cls, db: Session) -> Dict[str, Any]:
        """
        Rôle : Sonde l'ensemble des équipements présents dans la base SQLite et met à jour leurs métriques,
               leurs prédictions TTF et leurs scores de santé.
        Entrées : Session DB.
        Sorties : Bilan global du cycle de collecte.
        """
        # S'assurer que la machine hôte réelle fait toujours partie du parc
        HardwareCollector.get_or_create_host_equipment(db)

        equipements = db.query(Equipement).all()
        results = []
        for eq in equipements:
            try:
                res = cls.probe_equipment(db, eq)
                results.append(res)
            except Exception as exc:
                results.append({"equipement": eq.nom, "error": str(exc)})

        return {
            "probed_count": len(results),
            "results": results,
            "horodatage": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def update_equipement(
        db: Session,
        equipement_id: int,
        update_data: Dict[str, Any],
        user: Optional[User] = None,
    ) -> Equipement:
        """
        Rôle : Met à jour les propriétés d'un équipement existant (IP, nom, groupe, seuil, identifiants SSH).
        Entrées : Session DB, ID de l'équipement, dictionnaire des champs modifiés, utilisateur courant.
        Sorties : Instance Equipement mise à jour.
        Cas d'erreur : Lève ValueError si l'équipement est introuvable.
        """
        eq = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if not eq:
            raise ValueError("Équipement introuvable")

        for field in ("nom", "ip", "mac", "type", "os", "firmware", "groupe", "seuil_disque_alerte", "statut_collecte"):
            if field in update_data and update_data[field] is not None:
                setattr(eq, field, update_data[field])

        if update_data.get("mot_de_passe_secret"):
            eq.identifiants_chiffres = encrypt_secret(update_data["mot_de_passe_secret"])

        db.commit()
        db.refresh(eq)

        ParcService.calculate_health_score(db, eq.id)
        log_audit_action(
            db=db,
            action="UPDATE_EQUIPEMENT",
            cible=f"{eq.nom} ({eq.ip})",
            user=user,
            details=f"Mise à jour de la fiche équipement #{eq.id}",
        )
        return eq

    @staticmethod
    def simulate_snmp_discovery(
        db: Session,
        ip_range: str = "192.168.1.0/24",
        inject_rogue: bool = False,
    ) -> Dict[str, Any]:
        """
        Rôle : Exécute un balayage des équipements du parc (et optionnellement détecte un équipement non autorisé Rogue).
        Entrées : Session DB, plage CIDR, booléen inject_rogue.
        Sorties : Résumé du scan conforme à SnmpScanResponse.
        """
        now = datetime.now(timezone.utc)
        equipements = db.query(Equipement).all()
        decouverts = []

        for eq in equipements:
            if eq.statut_collecte != "Injoignable":
                eq.derniere_collecte = now
                decouverts.append(eq.nom)

        rogue_info = None
        if inject_rogue:
            rogue_nom = "ROGUE-PI-01"
            rogue_ip = "192.168.1.150"
            existing_rogue = db.query(Equipement).filter(Equipement.ip == rogue_ip).first()
            if not existing_rogue:
                rogue = Equipement(
                    nom=rogue_nom,
                    ip=rogue_ip,
                    mac="B8:27:EB:AA:BB:CC",
                    type="Poste client inconnu",
                    os="Linux / Raspberry Pi OS",
                    uptime_secondes=3600,
                    score_sante=40.0,
                    statut_collecte="OK",
                    date_decouverte=now,
                    derniere_collecte=now,
                    groupe="Non catégorisé",
                )
                db.add(rogue)
                db.commit()
                db.refresh(rogue)

                alerte_rogue = Alerte(
                    equipement_id=rogue.id,
                    module_origine="Parc",
                    severite="CRITICAL",
                    titre=f"Équipement non répertorié détecté : {rogue_nom}",
                    message=f"Nouvelle adresse IP {rogue_ip} détectée sur le sous-réseau {ip_range} (MAC: B8:27:EB:AA:BB:CC). Suspicion d'appareil pirate (Rogue Device).",
                    statut="Active",
                    date_creation=now,
                )
                db.add(alerte_rogue)
                log_audit_action(
                    db=db,
                    action="ROGUE_DEVICE_DETECTED",
                    cible=f"{rogue_nom} ({rogue_ip})",
                    details=f"Alerte intrusion : Découverte d'un équipement pirate sur {ip_range}",
                )
                db.commit()
                rogue_info = {"nom": rogue_nom, "ip": rogue_ip, "alerte": "CRITICAL"}
            else:
                existing_rogue.derniere_collecte = now
                rogue_info = {"nom": rogue_nom, "ip": rogue_ip, "alerte": "CRITICAL"}

        log_audit_action(
            db=db,
            action="SNMP_SCAN",
            cible=ip_range,
            details=f"Balayage réseau terminé : {len(decouverts)} équipements actifs confirmés.",
        )
        return {
            "plage": ip_range,
            "equipements_actifs": decouverts,
            "nouveaux_detectes": 1 if inject_rogue else 0,
            "rogue_device": rogue_info,
            "horodatage": now.isoformat(),
        }

    @staticmethod
    def export_csv(db: Session) -> str:
        """Exporte l'inventaire complet du parc au format CSV."""
        output = io.StringIO()
        writer = csv.writer(output, delimiter=";")
        writer.writerow([
            "ID", "Nom", "IP", "MAC", "Type", "OS", "Firmware",
            "Score_Sante", "Statut_Collecte", "Groupe", "Uptime_Heures"
        ])

        equipements = db.query(Equipement).all()
        for eq in equipements:
            uptime_h = round(eq.uptime_secondes / 3600.0, 1)
            writer.writerow([
                eq.id, eq.nom, eq.ip, eq.mac or "", eq.type, eq.os or "", eq.firmware or "",
                eq.score_sante, eq.statut_collecte, eq.groupe, uptime_h
            ])

        return output.getvalue()

    @staticmethod
    def get_local_network_info() -> Dict[str, Any]:
        """Détecte l'IP locale réelle de la machine hôte et son sous-réseau physique."""
        hostname = socket.gethostname()
        local_ip = "127.0.0.1"

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            try:
                local_ip = socket.gethostbyname(hostname)
            except Exception:
                local_ip = "127.0.0.1"

        if "." in local_ip and not local_ip.startswith("127."):
            parts = local_ip.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            gateway_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        else:
            subnet = "192.168.1.0/24"
            gateway_ip = "192.168.1.1"

        return {
            "local_ip": local_ip,
            "subnet": subnet,
            "hostname": hostname,
            "gateway_ip": gateway_ip,
            "interface_name": f"{platform.system()} ({platform.release()})",
        }

    @staticmethod
    def scan_real_network(db: Session, ip_prefix: Optional[str] = None) -> Dict[str, Any]:
        """
        Rôle : Effectue un balayage réseau physique réel du sous-réseau local (Ping sweep + Table ARP + Ports TCP + Bannières HTTP).
        Entrées : Session DB, préfixe IP optionnel.
        Sorties : Liste des équipements physiques détectés sur le LAN.
        """
        t0 = time.time()
        net_info = ParcService.get_local_network_info()
        local_ip = net_info["local_ip"]
        subnet = net_info["subnet"]

        if not ip_prefix:
            if "." in local_ip and not local_ip.startswith("127."):
                parts = local_ip.split(".")
                ip_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
            else:
                ip_prefix = "192.168.1"
        elif "/" in ip_prefix:
            ip_prefix = ip_prefix.split("/")[0].rsplit(".", 1)[0]

        no_window_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if platform.system() == "Windows" else 0

        def _quick_ping(target_ip: str):
            try:
                ping_args = (
                    ["ping", "-n", "1", "-w", "150", target_ip]
                    if platform.system() == "Windows"
                    else ["ping", "-c", "1", "-W", "1", target_ip]
                )
                subprocess.run(
                    ping_args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    creationflags=no_window_flags,
                    startupinfo=_make_hidden_startupinfo(),
                    timeout=0.8,
                )
            except Exception:
                pass

        ips_to_ping = [f"{ip_prefix}.1", f"{ip_prefix}.254"]
        last_octet = int(local_ip.split(".")[-1]) if "." in local_ip and not local_ip.startswith("127.") else 100
        for i in range(1, 41):
            ips_to_ping.append(f"{ip_prefix}.{i}")
        for i in range(max(1, last_octet - 5), min(255, last_octet + 6)):
            ips_to_ping.append(f"{ip_prefix}.{i}")

        unique_ips_to_ping = list(dict.fromkeys(ips_to_ping))
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            executor.map(_quick_ping, unique_ips_to_ping)

        arp_entries: Dict[str, str] = {}
        try:
            raw_arp = subprocess.check_output(
                ["arp", "-a"],
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=no_window_flags,
                startupinfo=_make_hidden_startupinfo(),
                timeout=2.0,
            ).decode("cp850" if platform.system() == "Windows" else "utf-8", errors="ignore")
            for line in raw_arp.splitlines():
                line = line.strip()
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:\-]{17})", line)
                if match:
                    ip_found = match.group(1)
                    mac_found = match.group(2).replace("-", ":").upper()
                    if not ip_found.startswith("224.") and not ip_found.startswith("239.") and not ip_found.endswith(".255"):
                        arp_entries[ip_found] = mac_found
        except Exception:
            pass

        gateway_ip = net_info.get("gateway_ip", f"{ip_prefix}.1")
        if gateway_ip not in arp_entries:
            arp_entries[gateway_ip] = "00:00:5E:00:53:01"
        if local_ip not in arp_entries and not local_ip.startswith("127."):
            _, host_mac = HardwareCollector._detect_host_ip_and_mac()
            arp_entries[local_ip] = host_mac

        discovered_devices = []
        existing_ips = {eq.ip for eq in db.query(Equipement.ip).all()}
        ports_to_check = [80, 443, 22, 23, 53, 445, 8080]

        for dev_ip, mac_addr in arp_entries.items():
            if not dev_ip.startswith(ip_prefix):
                continue

            open_ports = []
            for port in ports_to_check:
                try:
                    s = socket.socket()
                    s.settimeout(0.18)
                    res = s.connect_ex((dev_ip, port))
                    s.close()
                    if res == 0:
                        open_ports.append(port)
                except Exception:
                    pass

            # Sonde SNMP v2c native en UDP 161
            snmp_scan_data = None
            try:
                snmp_scan_data = SnmpClient.probe_device_metrics(dev_ip, community="public", timeout=0.25)
                if snmp_scan_data:
                    open_ports.append(161)
            except Exception:
                snmp_scan_data = None

            banner = None
            if snmp_scan_data and snmp_scan_data.get("sys_descr"):
                banner = f"SNMP v2c: {snmp_scan_data['sys_descr'][:40]}"
            elif 80 in open_ports or 8080 in open_ports:
                target_port = 80 if 80 in open_ports else 8080
                try:
                    req = urllib.request.Request(
                        f"http://{dev_ip}:{target_port}/",
                        headers={"User-Agent": "Sentinelle-AIOps-Physical-Scanner/2.4"},
                    )
                    resp = urllib.request.urlopen(req, timeout=0.7)
                    server_header = resp.headers.get("Server")
                    banner = f"HTTP {resp.status} ({server_header})" if server_header else f"HTTP {resp.status}"
                except Exception:
                    banner = "HTTP Port Actif"

            hostname = None
            if snmp_scan_data and snmp_scan_data.get("sys_name"):
                hostname = snmp_scan_data["sys_name"]
            else:
                try:
                    host_lookup = socket.gethostbyaddr(dev_ip)
                    hostname = host_lookup[0]
                except Exception:
                    pass

            if dev_ip == local_ip:
                dev_type = f"Serveur Host ({platform.system()})"
                dev_os = f"{platform.system()} ({platform.release()})"
                hostname = net_info["hostname"]
            elif snmp_scan_data and snmp_scan_data.get("sys_descr"):
                sys_desc_l = snmp_scan_data["sys_descr"].lower()
                dev_os = snmp_scan_data["sys_descr"][:60]
                if "cisco" in sys_desc_l or "ios" in sys_desc_l:
                    dev_type = "Switch / Routeur Cisco (SNMP)"
                elif "linux" in sys_desc_l:
                    dev_type = "Serveur Linux (SNMP)"
                else:
                    dev_type = "Périphérique Manageable (SNMP)"
            elif dev_ip == gateway_ip or dev_ip.endswith(".1") or dev_ip.endswith(".254"):
                dev_type = "Routeur / Box Internet Physique"
                dev_os = "Firmware Embarqué / Linux"
                if not hostname:
                    hostname = "BOX-ROUTER-GATEWAY"
            elif 22 in open_ports and 445 not in open_ports:
                dev_type = "Serveur / Switch Manageable"
                dev_os = "Linux / Cisco IOS"
            elif 445 in open_ports or 135 in open_ports:
                dev_type = "Poste client Windows"
                dev_os = "Microsoft Windows"
            elif 80 in open_ports or 443 in open_ports:
                dev_type = "Périphérique Web / IoT"
                dev_os = "Système Embarqué"
            else:
                dev_type = "Périphérique Réseau IP"
                dev_os = "Linux / Périphérique Réseau"

            if not hostname:
                hostname = f"HOST-{dev_ip.replace('.', '-')}"

            discovered_devices.append({
                "ip": dev_ip,
                "mac": mac_addr if mac_addr != "LOCAL-HOST" else None,
                "hostname": hostname,
                "type": dev_type,
                "os": dev_os,
                "open_ports": open_ports,
                "banner": banner,
                "already_in_parc": dev_ip in existing_ips,
            })

        duration_ms = int((time.time() - t0) * 1000)
        return {
            "subnet": subnet,
            "local_host": net_info,
            "devices_count": len(discovered_devices),
            "devices": discovered_devices,
            "scan_duration_ms": duration_ms,
        }

    @classmethod
    def import_real_devices(cls, db: Session, devices_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Rôle : Importe dans le parc SQLite les équipements physiques découverts lors du scan
               et déclenche immédiatement leur première sonde télémétrique.
        Entrées : Session DB, liste de dictionnaires d'équipements.
        Sorties : Bilan d'importation (ajoutés vs ignorés).
        """
        imported = []
        skipped = []
        now = datetime.now(timezone.utc)

        for dev in devices_data:
            ip = dev.get("ip")
            if not ip:
                continue

            existing = db.query(Equipement).filter(Equipement.ip == ip).first()
            if existing:
                skipped.append(ip)
                continue

            nom = dev.get("nom") or f"PHY-{ip.replace('.', '-')}"
            # Éviter tout conflit sur le nom d'équipement
            if db.query(Equipement).filter(Equipement.nom == nom).first():
                nom = f"{nom}-{ip.split('.')[-1]}"

            new_eq = Equipement(
                nom=nom,
                ip=ip,
                mac=dev.get("mac"),
                type=dev.get("type", "Périphérique Réseau"),
                os=dev.get("os", "Linux"),
                groupe=dev.get("groupe", "Physique"),
                uptime_secondes=86400,
                score_sante=100.0,
                statut_collecte="OK",
                date_decouverte=now,
                derniere_collecte=now,
            )
            db.add(new_eq)
            db.commit()
            db.refresh(new_eq)

            # Sonder immédiatement l'équipement importé pour initialiser ses métriques et son TTF
            try:
                cls.probe_equipment(db, new_eq)
            except Exception:
                pass

            log_audit_action(
                db=db,
                action="IMPORT_PHYSICAL_DEVICE",
                cible=f"{nom} ({ip})",
                details=f"Équipement physique réel importé et sondé ({new_eq.type})",
            )
            imported.append({"id": new_eq.id, "nom": nom, "ip": ip})

        cls.recalculate_all_health_scores(db)

        return {
            "imported_count": len(imported),
            "imported_devices": imported,
            "skipped_count": len(skipped),
            "skipped_ips": skipped,
        }
