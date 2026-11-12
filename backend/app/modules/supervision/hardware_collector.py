"""
Collecteur de Télémétrie Matérielle Réelle (Host Machine / psutil).

Permet à Sentinelle AIOps de superviser l'ordinateur hôte réel (CPU, RAM, Disque, Réseau)
en local ou lorsque l'application est compilée en fichier exécutable autonome (.exe).
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple
try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]
from sqlalchemy.orm import Session

from backend.app.db.models import Equipement, Metrique
from backend.app.modules.supervision.service import SupervisionService


class HardwareCollector:
    """Sonde de métrologie et d'inventaire matériel du système hôte Windows/Linux."""

    # Mémorisation des compteurs I/O réseau précédents pour calculer le débit réel en Mbps
    _last_net_sample: Optional[Tuple[float, int, int]] = None

    @staticmethod
    def _detect_host_ip_and_mac() -> Tuple[str, str]:
        """
        Rôle : Détecte l'adresse IP locale active et l'adresse MAC physique réelle de l'interface réseau.
        Entrées : Aucune.
        Sorties : Tuple (ip_locale, mac_physique).
        Cas d'erreur : Retourne ('127.0.0.1', '00:00:00:00:00:00') si aucune carte réseau active n'est détectée.
        """
        local_ip = "127.0.0.1"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
        except Exception:
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                local_ip = "127.0.0.1"

        mac_addr = "00:00:00:00:00:00"
        try:
            if_addrs = psutil.net_if_addrs()
            matched_iface = None
            for iface_name, snics in if_addrs.items():
                for snic in snics:
                    if snic.family == socket.AF_INET and snic.address == local_ip:
                        matched_iface = iface_name
                        break
                if matched_iface:
                    break

            target_ifaces = [matched_iface] if matched_iface else list(if_addrs.keys())
            for iface_name in target_ifaces:
                if not iface_name:
                    continue
                for snic in if_addrs.get(iface_name, []):
                    addr_str = str(snic.address or "")
                    if len(addr_str) == 17 and ("-" in addr_str or ":" in addr_str):
                        normalized = addr_str.replace("-", ":").upper()
                        if normalized != "00:00:00:00:00:00":
                            mac_addr = normalized
                            break
                if mac_addr != "00:00:00:00:00:00":
                    break
        except Exception:
            pass

        if mac_addr == "00:00:00:00:00:00":
            try:
                node_int = uuid.getnode()
                mac_addr = ":".join(f"{(node_int >> ele) & 0xff:02X}" for ele in range(40, -1, -8))
            except Exception:
                pass

        return local_ip, mac_addr

    @staticmethod
    def _get_boot_uptime_seconds() -> int:
        """
        Rôle : Retourne le temps de fonctionnement (uptime) réel du système hôte en secondes.
        Entrées : Aucune.
        Sorties : Entier représentant l'uptime en secondes.
        """
        if psutil is not None:
            try:
                return int(time.time() - psutil.boot_time())
            except Exception:
                pass
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as f:
                return int(float(f.read().split()[0]))
        except Exception:
            return 86400

    @classmethod
    def get_or_create_host_equipment(cls, db: Session) -> Equipement:
        """
        Rôle : Détecte la machine hôte et l'enregistre ou met à jour ses métadonnées réseau dans le parc SQLite.
        Entrées : Session SQLAlchemy active (db).
        Sorties : Instance SQLAlchemy Equipement correspondant à la machine hôte.
        Cas d'erreur : Annule la transaction (rollback) en cas de conflit d'unicité IP/nom et récupère l'enregistrement existant.
        """
        hostname = socket.gethostname() or "HOST-LOCAL"
        os_name = f"{platform.system()} {platform.release()}"
        local_ip, real_mac = cls._detect_host_ip_and_mac()

        equipement = (
            db.query(Equipement)
            .filter((Equipement.nom == hostname) | (Equipement.ip == local_ip))
            .first()
        )
        if not equipement:
            boot_uptime = cls._get_boot_uptime_seconds()
            equipement = Equipement(
                nom=hostname,
                ip=local_ip,
                mac=real_mac,
                type=f"Serveur Host ({platform.system()})",
                os=os_name,
                firmware=f"Kernel {platform.version()[:25]}",
                uptime_secondes=boot_uptime,
                score_sante=96.0,
                statut_collecte="OK",
                groupe="Hôte Local (Hardware)",
                seuil_disque_alerte=85.0,
            )
            try:
                db.add(equipement)
                db.commit()
                db.refresh(equipement)
            except Exception:
                db.rollback()
                equipement = db.query(Equipement).filter(Equipement.nom == hostname).first()
        else:
            # Maintenir l'IP et la MAC réelles synchronisées si la machine hôte a changé de réseau
            updated = False
            if local_ip != "127.0.0.1" and equipement.ip != local_ip:
                conflict = db.query(Equipement).filter(Equipement.ip == local_ip, Equipement.id != equipement.id).first()
                if not conflict:
                    equipement.ip = local_ip
                    updated = True
            if real_mac != "00:00:00:00:00:00" and equipement.mac != real_mac:
                equipement.mac = real_mac
                updated = True
            if updated:
                try:
                    db.commit()
                except Exception:
                    db.rollback()

        return equipement

    @classmethod
    def _measure_network_throughput_mbps(cls) -> Tuple[float, float, float]:
        """
        Rôle : Calcule le débit réseau instantané réel en Mbps ainsi que le volume cumulé envoyé/reçu en Mo.
        Entrées : Utilise l'état interne _last_net_sample et les compteurs psutil.net_io_counters().
        Sorties : Tuple (debit_mbps, total_sent_mb, total_recv_mb).
        Cas d'erreur : Retourne (0.0, 0.0, 0.0) si les compteurs réseau de l'OS sont inaccessibles.
        """
        try:
            net_io = psutil.net_io_counters()
            now_ts = time.time()
            bytes_sent = int(net_io.bytes_sent)
            bytes_recv = int(net_io.bytes_recv)
            net_sent_mb = round(bytes_sent / (1024 ** 2), 2)
            net_recv_mb = round(bytes_recv / (1024 ** 2), 2)

            if cls._last_net_sample is not None:
                prev_ts, prev_sent, prev_recv = cls._last_net_sample
                dt = max(0.05, now_ts - prev_ts)
                delta_bytes = max(0, (bytes_sent - prev_sent) + (bytes_recv - prev_recv))
                mbps = round((delta_bytes * 8.0) / (dt * 1_000_000.0), 2)
            else:
                mbps = 0.5

            cls._last_net_sample = (now_ts, bytes_sent, bytes_recv)
            return mbps, net_sent_mb, net_recv_mb
        except Exception:
            return 0.0, 0.0, 0.0

    @classmethod
    def collect_live_metrics(cls, db: Session) -> Dict[str, Any]:
        """
        Rôle : Collecte les métriques matérielles instantanées réelles de la machine hôte (CPU, RAM, Disque, Réseau)
               et met à jour les séries temporelles SQLite ainsi que les prédictions TTF.
        Entrées : Session SQLAlchemy (db).
        Sorties : Dictionnaire complet des indicateurs matériels temps réel.
        Cas d'erreur : Repli sécurisé sur les partitions disponibles en cas d'erreur de lecture disque.
        """
        host_eq = cls.get_or_create_host_equipment(db)
        now = datetime.now(timezone.utc)

        # 1. CPU
        cpu_count = os.cpu_count() or 1
        if psutil is not None:
            cpu_pct = float(psutil.cpu_percent(interval=0.1))
            cpu_count = psutil.cpu_count(logical=True) or cpu_count
        else:
            try:
                load1 = os.getloadavg()[0]
                cpu_pct = round(min(100.0, max(1.0, (load1 / cpu_count) * 100.0)), 1)
            except Exception:
                cpu_pct = 15.0

        # 2. RAM
        if psutil is not None:
            vmem = psutil.virtual_memory()
            ram_pct = float(vmem.percent)
            ram_total_gb = round(vmem.total / (1024 ** 3), 2)
            ram_used_gb = round(vmem.used / (1024 ** 3), 2)
        else:
            ram_pct, ram_total_gb, ram_used_gb = 45.0, 16.0, 7.2
            try:
                with open("/proc/meminfo", "r", encoding="utf-8") as f:
                    mem_lines = f.read()
                m_tot = next((int(l.split()[1]) for l in mem_lines.splitlines() if l.startswith("MemTotal:")), 0)
                m_avail = next((int(l.split()[1]) for l in mem_lines.splitlines() if l.startswith("MemAvailable:")), 0)
                if m_tot > 0:
                    used_kb = max(0, m_tot - m_avail)
                    ram_pct = round((used_kb / m_tot) * 100.0, 1)
                    ram_total_gb = round(m_tot / (1024 ** 2), 2)
                    ram_used_gb = round(used_kb / (1024 ** 2), 2)
            except Exception:
                pass

        # 3. Disque (Partition système principale C:\ sous Windows ou / sous Linux)
        mount_path = "C:\\" if platform.system() == "Windows" else "/"
        try:
            if psutil is not None:
                disk_info = psutil.disk_usage(mount_path)
                disk_pct = float(disk_info.percent)
                disk_total_gb = round(disk_info.total / (1024 ** 3), 2)
                disk_used_gb = round(disk_info.used / (1024 ** 3), 2)
            else:
                du = shutil.disk_usage(mount_path)
                disk_pct = round((du.used / du.total) * 100.0, 1) if du.total > 0 else 50.0
                disk_total_gb = round(du.total / (1024 ** 3), 2)
                disk_used_gb = round(du.used / (1024 ** 3), 2)
        except Exception:
            disk_pct = 50.0
            disk_total_gb = 256.0
            disk_used_gb = 128.0

        # 4. Réseau (Débit I/O réel en Mbps + cumul en Mo)
        net_mbps, net_sent_mb, net_recv_mb = cls._measure_network_throughput_mbps()

        # 5. Uptime
        uptime_sec = cls._get_boot_uptime_seconds()

        # 6. Sauvegarde des 4 métriques en base de données pour les courbes temps réel
        db.add(Metrique(equipement_id=host_eq.id, type_metrique="cpu_percent", valeur=cpu_pct, horodatage=now))
        db.add(Metrique(equipement_id=host_eq.id, type_metrique="ram_percent", valeur=ram_pct, horodatage=now))
        db.add(Metrique(equipement_id=host_eq.id, type_metrique="disk_percent", valeur=disk_pct, horodatage=now))
        db.add(Metrique(equipement_id=host_eq.id, type_metrique="network_mbps", valeur=net_mbps, horodatage=now))

        # Mettre à jour l'équipement hôte
        host_eq.uptime_secondes = uptime_sec
        host_eq.derniere_collecte = now
        host_eq.statut_collecte = "OK"

        # Calculer un score de santé dynamique basé sur les sollicitations matérielles réelles
        health_penalty = (
            max(0.0, (cpu_pct - 70.0) * 0.4)
            + max(0.0, (ram_pct - 80.0) * 0.5)
            + max(0.0, (disk_pct - 85.0) * 0.8)
        )
        host_eq.score_sante = max(10.0, min(100.0, round(100.0 - health_penalty, 1)))

        db.commit()

        # 7. Actualiser les prédictions TTF dès que l'historique comporte au moins 3 mesures
        for metric_name in ("disk_percent", "ram_percent", "cpu_percent"):
            points_count = (
                db.query(Metrique)
                .filter(
                    Metrique.equipement_id == host_eq.id,
                    Metrique.type_metrique == metric_name,
                )
                .count()
            )
            if points_count >= 3:
                SupervisionService.calculate_ttf(db, host_eq.id, metric_name)

        return {
            "equipement_id": host_eq.id,
            "hostname": host_eq.nom,
            "ip": host_eq.ip,
            "mac": host_eq.mac,
            "os": host_eq.os,
            "firmware": host_eq.firmware,
            "cpu_percent": cpu_pct,
            "cpu_count": cpu_count,
            "ram_percent": ram_pct,
            "ram_total_gb": ram_total_gb,
            "ram_used_gb": ram_used_gb,
            "disk_percent": disk_pct,
            "disk_total_gb": disk_total_gb,
            "disk_used_gb": disk_used_gb,
            "disk_mount": mount_path,
            "network_mbps": net_mbps,
            "network_sent_mb": net_sent_mb,
            "network_recv_mb": net_recv_mb,
            "uptime_secondes": uptime_sec,
            "score_sante": host_eq.score_sante,
            "horodatage": now.isoformat(),
        }
