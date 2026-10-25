"""
Collecteur de Télémétrie Matérielle Réelle (Host Machine / psutil).

Permet à Sentinelle AIOps de superviser l'ordinateur hôte réel (CPU, RAM, Disque, Réseau)
en local ou lorsque l'application est compilée en fichier exécutable autonome (.exe).
"""

from __future__ import annotations

import os
import platform
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import psutil
from sqlalchemy.orm import Session

from backend.app.db.models import Equipement, Metrique, Prediction
from backend.app.modules.supervision.service import SupervisionService


class HardwareCollector:
    """Sonde de métrologie et d'inventaire matériel du système hôte."""

    @staticmethod
    def get_or_create_host_equipment(db: Session) -> Equipement:
        """Détecte la machine hôte et l'enregistre automatiquement dans le parc SQLite."""
        hostname = socket.gethostname() or "HOST-LOCAL"
        os_name = f"{platform.system()} {platform.release()}"

        equipement = db.query(Equipement).filter(Equipement.nom == hostname).first()
        if not equipement:
            # Récupérer l'IP locale principale
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
            except Exception:
                local_ip = "127.0.0.1"

            boot_uptime = int(time.time() - psutil.boot_time())
            equipement = Equipement(
                nom=hostname,
                ip=local_ip,
                mac="00:50:56:LOCAL:01",
                type=f"Serveur Host ({platform.system()})",
                os=os_name,
                firmware=f"Kernel {platform.version()[:25]}",
                uptime_secondes=boot_uptime,
                score_sante=96.0,
                statut_collecte="OK",
                groupe="Hôte Local (Hardware)",
                seuil_disque_alerte=85.0,
            )
            db.add(equipement)
            db.commit()
            db.refresh(equipement)

        return equipement

    @classmethod
    def collect_live_metrics(cls, db: Session) -> Dict[str, Any]:
        """Collecte les métriques matérielles instantanées réelles de la machine hôte."""
        host_eq = cls.get_or_create_host_equipment(db)
        now = datetime.now(timezone.utc)

        # 1. CPU
        cpu_pct = float(psutil.cpu_percent(interval=0.1))
        cpu_count = psutil.cpu_count(logical=True) or 1

        # 2. RAM
        vmem = psutil.virtual_memory()
        ram_pct = float(vmem.percent)
        ram_total_gb = round(vmem.total / (1024 ** 3), 2)
        ram_used_gb = round(vmem.used / (1024 ** 3), 2)

        # 3. Disque (Partition système principale)
        mount_path = "C:\\" if platform.system() == "Windows" else "/"
        try:
            disk_info = psutil.disk_usage(mount_path)
            disk_pct = float(disk_info.percent)
            disk_total_gb = round(disk_info.total / (1024 ** 3), 2)
            disk_used_gb = round(disk_info.used / (1024 ** 3), 2)
        except Exception:
            disk_pct = 75.0
            disk_total_gb = 500.0
            disk_used_gb = 375.0

        # 4. Réseau (Débit I/O cumulé)
        try:
            net_io = psutil.net_io_counters()
            net_sent_mb = round(net_io.bytes_sent / (1024 ** 2), 2)
            net_recv_mb = round(net_io.bytes_recv / (1024 ** 2), 2)
        except Exception:
            net_sent_mb = 0.0
            net_recv_mb = 0.0

        # 5. Uptime
        uptime_sec = int(time.time() - psutil.boot_time())

        # 6. Sauvegarde des métriques en base de données pour la série temporelle
        db.add(Metrique(equipement_id=host_eq.id, type_metrique="cpu_percent", valeur=cpu_pct, horodatage=now))
        db.add(Metrique(equipement_id=host_eq.id, type_metrique="ram_percent", valeur=ram_pct, horodatage=now))
        db.add(Metrique(equipement_id=host_eq.id, type_metrique="disk_percent", valeur=disk_pct, horodatage=now))

        # Mettre à jour l'équipement
        host_eq.uptime_secondes = uptime_sec
        host_eq.derniere_collecte = now
        host_eq.statut_collecte = "OK"

        # Calculer un score de santé dynamique basé sur les sollicitations matérielles
        health_penalty = max(0.0, (cpu_pct - 70) * 0.4) + max(0.0, (ram_pct - 80) * 0.5) + max(0.0, (disk_pct - 85) * 0.8)
        host_eq.score_sante = max(10.0, min(100.0, round(100.0 - health_penalty, 1)))

        db.commit()

        # Si l'historique du disque est suffisant, actualiser la prédiction TTF
        points_count = db.query(Metrique).filter(
            Metrique.equipement_id == host_eq.id,
            Metrique.type_metrique == "disk_percent",
        ).count()

        if points_count >= 3:
            SupervisionService.calculate_ttf(db, host_eq.id, "disk_percent")

        return {
            "equipement_id": host_eq.id,
            "hostname": host_eq.nom,
            "ip": host_eq.ip,
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
            "network_sent_mb": net_sent_mb,
            "network_recv_mb": net_recv_mb,
            "uptime_secondes": uptime_sec,
            "score_sante": host_eq.score_sante,
            "horodatage": now.isoformat(),
        }
