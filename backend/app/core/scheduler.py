"""
Ordonnanceur de tâches d'arrière-plan (Background Scheduler) pour Sentinelle AIOps.

Exécute de manière autonome et continue :
  1. La collecte des métriques matérielles réelles de la machine hôte (CPU, RAM, Disque, Débit Réseau).
  2. Le sondage périodique (Ping ICMP / TCP / SSH) de tous les équipements du parc.
  3. La purge automatique des métriques de plus de 30 jours (rétention SQLite).
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from backend.app.db.session import SessionLocal
from backend.app.modules.parc.service import ParcService
from backend.app.modules.supervision.hardware_collector import HardwareCollector
from backend.app.modules.supervision.service import SupervisionService

logger = logging.getLogger("sentinelle.scheduler")

_scheduler_instance: Any = None
_scheduler_lock = threading.Lock()


def _job_collect_host_metrics() -> None:
    """
    Rôle : Tâche planifiée de collecte matérielle temps réel (psutil) sur la machine hôte.
    """
    try:
        with SessionLocal() as db:
            HardwareCollector.collect_live_metrics(db)
    except Exception as exc:
        logger.warning("Erreur lors de la collecte périodique hôte : %s", exc)


def _job_probe_network_parc() -> None:
    """
    Rôle : Tâche planifiée de sondage actif (ICMP/TCP/SSH) des équipements du parc.
    """
    try:
        with SessionLocal() as db:
            ParcService.probe_all_equipments(db)
    except Exception as exc:
        logger.warning("Erreur lors du sondage périodique du parc : %s", exc)


def _job_purge_old_metrics() -> None:
    """
    Rôle : Tâche planifiée de purge des métriques dépassant la rétention de 30 jours.
    """
    try:
        with SessionLocal() as db:
            SupervisionService.purge_old_metrics(db, retention_days=30)
    except Exception as exc:
        logger.warning("Erreur lors de la purge périodique SQLite : %s", exc)


def _job_security_scan() -> None:
    """
    Rôle : Lit les journaux d'authentification de l'hôte puis analyse la fenêtre courante (détection d'intrusion).
    """
    try:
        from backend.app.modules.securite.service import SecurityService
        with SessionLocal() as db:
            SecurityService.run_real_security_scan(db, audit=False)
    except Exception as exc:
        logger.warning("Erreur lors de l'analyse périodique de sécurité : %s", exc)


def start_background_scheduler() -> None:
    """
    Rôle : Démarre le planificateur APScheduler en arrière-plan (sauf si désactivé pendant les tests).
    Entrées : Aucune.
    Sorties : Aucune.
    """
    global _scheduler_instance
    if os.environ.get("SENTINELLE_DISABLE_SCHEDULER") == "1":
        return

    with _scheduler_lock:
        if _scheduler_instance is not None:
            return

        try:
            from apscheduler.schedulers.background import BackgroundScheduler

            scheduler = BackgroundScheduler(daemon=True)
            scheduler.add_job(
                _job_collect_host_metrics,
                "interval",
                seconds=45,
                id="host_hardware_collector",
                replace_existing=True,
                max_instances=1,
            )
            scheduler.add_job(
                _job_probe_network_parc,
                "interval",
                seconds=180,
                id="parc_network_prober",
                replace_existing=True,
                max_instances=1,
            )
            scheduler.add_job(
                _job_purge_old_metrics,
                "interval",
                hours=12,
                id="sqlite_retention_purge",
                replace_existing=True,
                max_instances=1,
            )
            from backend.app.core.config import settings
            scheduler.add_job(
                _job_security_scan,
                "interval",
                minutes=settings.SECURITY_SCAN_INTERVAL_MINUTES,
                id="security_log_analysis",
                replace_existing=True,
                max_instances=1,
            )
            scheduler.start()
            _scheduler_instance = scheduler
        except Exception as exc:
            logger.warning("APScheduler non démarré : %s", exc)


def stop_background_scheduler() -> None:
    """
    Rôle : Arrête proprement le planificateur d'arrière-plan à l'extinction du serveur.
    """
    global _scheduler_instance
    with _scheduler_lock:
        if _scheduler_instance is not None:
            try:
                _scheduler_instance.shutdown(wait=False)
            except Exception as exc:
                logger.warning("Arrêt du planificateur en échec : %s", exc)
            _scheduler_instance = None

