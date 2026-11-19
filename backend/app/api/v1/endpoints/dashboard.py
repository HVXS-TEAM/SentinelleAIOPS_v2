"""
Endpoints REST – Module Dashboard Global & Vue d'ensemble Opérationnelle.

Routes :
  GET  /dashboard/summary  → Vue consolidée des KPIs, alertes, TTF, et modules
  POST /dashboard/refresh  → Rafraîchissement actif des sondes et métriques consolidées
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.api.deps import ROLES_OPERATEURS, get_current_user, require_roles
from backend.app.db.session import get_db
from backend.app.modules.dashboard.service import DashboardService
from backend.app.modules.parc.service import ParcService
from backend.app.modules.supervision.hardware_collector import HardwareCollector

import logging
logger = logging.getLogger("sentinelle.api.dashboard")


router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
    dependencies=[Depends(get_current_user)],
)


@router.get("/summary", summary="Synthèse globale et KPIs multi-modules")
def get_dashboard_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    """
    Rôle : Retourne la synthèse temps réel de l'état opérationnel Sentinelle AIOps :
    - KPIs généraux (indice de résilience, santé moyenne, alertes critiques)
    - Répartition de la santé du parc
    - Alertes actives récentes corrélées
    - Prédictions de panne les plus imminentes (TTF)
    - Courbe temporelle réelle (télémétrie SQLite + projection régression linéaire)
    - Journal des dernières actions d'audit
    - Statut des 4 modules spécialisés
    """
    return DashboardService.get_summary(db)


@router.post(
    "/refresh",
    summary="Rafraîchissement actif des sondes matérielles et réseau",
    dependencies=[Depends(require_roles(ROLES_OPERATEURS))],
)
def refresh_dashboard_data(db: Session = Depends(get_db)) -> dict[str, Any]:
    """
    Rôle : Déclenche une collecte matérielle live (psutil) et sonde tous les équipements du parc,
    puis retourne le résumé consolidé mis à jour.
    """
    try:
        HardwareCollector.collect_live_metrics(db)
        ParcService.probe_all_equipments(db)
    except Exception as exc:
        logger.warning("Rafraîchissement du tableau de bord : collecte des métriques de l'hôte en échec : %s", exc)
    return DashboardService.get_summary(db)
