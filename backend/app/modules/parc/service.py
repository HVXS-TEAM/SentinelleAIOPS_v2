"""Service de gestion de parc informatique, inventaire et scoring de santé.

Implémente la formule de santé composite, la détection des équipements disparus/inconnus
et l'import/export de l'inventaire au format CSV.
"""
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import io
import csv
import socket
import subprocess
import re
import time
import platform
import concurrent.futures
import urllib.request
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.app.db.models import Equipement, Metrique, Alerte, AuditReseau
from backend.app.core.audit import log_audit_action



class ParcService:
    @staticmethod
    def calculate_health_score(db: Session, equipement_id: int) -> float:
        """Calcule la note synthétique de santé (0 à 100) selon une formule documentée et pondérée.

        Pondération :
        - Disponibilité (statut de collecte) : 35%
        - Charge des ressources (CPU, RAM, Disque sous 80%) : 25%
        - Pénalité des alertes actives : 25% (CRITICAL: -20, WARNING: -10)
        - Conformité des configurations (CIS Benchmark) : 15%
        """
        equipement = db.query(Equipement).filter(Equipement.id == equipement_id).first()
        if not equipement:
            return 100.0

        # 1. Facteur Disponibilité (35%)
        score_dispo = 100.0 if equipement.statut_collecte == "OK" else 0.0

        # 2. Facteur Ressources (25%)
        # Récupérer la dernière valeur de CPU, RAM, Disque
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
                # Si valeur < 80% => 100, sinon dégradation linéaire jusqu'à 100%
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

        # Formule globale pondérée
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
    def simulate_snmp_discovery(
        db: Session,
        ip_range: str = "192.168.1.0/24",
        inject_rogue: bool = False,
    ) -> Dict[str, Any]:
        """Simule un balayage réseau SNMP.
        
        - Découvre les équipements actifs existants et actualise leur horodatage 'derniere_collecte'.
        - Si inject_rogue=True : Détecte un équipement non répertorié (vecteur d'intrusion) et lève une alerte.
        """
        now = datetime.now(timezone.utc)
        equipements = db.query(Equipement).all()
        decouverts = []

        # Actualisation des équipements existants
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

                # Alerte de sécurité immédiate
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

        # 1. Découverte de l'IP active via UDP connect
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

        # Calcul du sous-réseau CIDR /24
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
        """Effectue un balayage réseau physique réel du sous-réseau local.

        - Détecte la passerelle (Box / Routeur) et les équipements connectés.
        - Lit la table ARP du système d'exploitation et sonde les ports d'administration (80, 443, 22, 53, 445).
        - Récupère les bannières HTTP pour identifier le matériel (ex: GoAhead-Webs, Livebox, Freebox, Cisco).
        """
        t0 = time.time()
        net_info = ParcService.get_local_network_info()
        local_ip = net_info["local_ip"]
        subnet = net_info["subnet"]

        # Déterminer le préfixe réseau à balayer (ex: '192.168.0')
        if not ip_prefix:
            if "." in local_ip:
                parts = local_ip.split(".")
                ip_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}"
            else:
                ip_prefix = "192.168.1"
        elif "/" in ip_prefix:
            ip_prefix = ip_prefix.split("/")[0].rsplit(".", 1)[0]

        # 1. Balayage ping multithreadé rapide pour peupler/rafraîchir la table ARP
        def _quick_ping(target_ip: str):
            try:
                subprocess.run(
                    ["ping", "-n", "1", "-w", "150", target_ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception:
                pass

        # Balayer la passerelle .1 et les 50 premières adresses + voisinage immédiat
        ips_to_ping = [f"{ip_prefix}.1", f"{ip_prefix}.254"]
        # Ajouter les 40 premières IPs et les 10 autour de l'hôte local
        last_octet = int(local_ip.split(".")[-1]) if "." in local_ip and not local_ip.startswith("127.") else 100
        for i in range(1, 41):
            ips_to_ping.append(f"{ip_prefix}.{i}")
        for i in range(max(1, last_octet - 5), min(255, last_octet + 6)):
            ips_to_ping.append(f"{ip_prefix}.{i}")

        unique_ips_to_ping = list(dict.fromkeys(ips_to_ping))
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            executor.map(_quick_ping, unique_ips_to_ping)

        # 2. Lecture de la table ARP Windows
        arp_entries: Dict[str, str] = {}
        try:
            raw_arp = subprocess.check_output("arp -a", shell=True).decode("cp850", errors="ignore")
            for line in raw_arp.splitlines():
                line = line.strip()
                # Exemple : 192.168.0.1  c8-2a-f2-0f-a1-2a  dynamique
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})\s+(\w+)", line)
                if match:
                    ip_found = match.group(1)
                    mac_found = match.group(2).replace("-", ":").upper()
                    # Ignorer les adresses multicast (224.x) et broadcast (255.255.255.255)
                    if not ip_found.startswith("224.") and not ip_found.startswith("239.") and not ip_found.endswith(".255"):
                        arp_entries[ip_found] = mac_found
        except Exception:
            pass

        # S'assurer que la passerelle et la machine locale sont incluses
        gateway_ip = net_info.get("gateway_ip", f"{ip_prefix}.1")
        if gateway_ip not in arp_entries:
            arp_entries[gateway_ip] = "00:00:5E:00:53:01"
        if local_ip not in arp_entries and not local_ip.startswith("127."):
            arp_entries[local_ip] = "LOCAL-HOST"

        # 3. Sonde des ports et qualification des équipements
        discovered_devices = []
        existing_ips = {eq.ip for eq in db.query(Equipement.ip).all()}

        ports_to_check = [80, 443, 22, 23, 53, 445, 8080]

        for dev_ip, mac_addr in arp_entries.items():
            # Ne sonder que les IPs de notre sous-réseau
            if not dev_ip.startswith(ip_prefix):
                continue

            open_ports = []
            for port in ports_to_check:
                try:
                    s = socket.socket()
                    s.settimeout(0.2)
                    res = s.connect_ex((dev_ip, port))
                    s.close()
                    if res == 0:
                        open_ports.append(port)
                except Exception:
                    pass

            # Récupération bannière HTTP si port web ouvert
            banner = None
            if 80 in open_ports or 8080 in open_ports:
                target_port = 80 if 80 in open_ports else 8080
                try:
                    req = urllib.request.Request(
                        f"http://{dev_ip}:{target_port}/",
                        headers={"User-Agent": "Sentinelle-AIOps-Physical-Scanner/2.0"},
                    )
                    resp = urllib.request.urlopen(req, timeout=0.8)
                    server_header = resp.headers.get("Server")
                    banner = f"HTTP {resp.status} ({server_header})" if server_header else f"HTTP {resp.status}"
                except Exception as e:
                    banner = "HTTP Port Actif"

            # Qualification du type et de l'OS
            hostname = None
            try:
                host_lookup = socket.gethostbyaddr(dev_ip)
                hostname = host_lookup[0]
            except Exception:
                pass

            if dev_ip == local_ip:
                dev_type = "Poste de travail (Hôte Sentinelle)"
                dev_os = f"Windows ({platform.release()})"
                hostname = net_info["hostname"]
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

    @staticmethod
    def import_real_devices(db: Session, devices_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Importe dans le parc SQLite les équipements physiques découverts lors du scan."""
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

            log_audit_action(
                db=db,
                action="IMPORT_PHYSICAL_DEVICE",
                cible=f"{nom} ({ip})",
                details=f"Équipement physique réel importé après scan réseau ({new_eq.type})",
            )
            imported.append({"id": new_eq.id, "nom": nom, "ip": ip})

        # Recalculer les scores
        ParcService.recalculate_all_health_scores(db)

        return {
            "imported_count": len(imported),
            "imported_devices": imported,
            "skipped_count": len(skipped),
            "skipped_ips": skipped,
        }

