"""
Endpoints REST – Module Dashboard Global & Vue d'ensemble Opérationnelle.

Routes :
  GET  /dashboard/summary  → Vue consolidée des KPIs, alertes, TTF, et modules
  POST /dashboard/refresh  → Rafraîchissement des calculs et métriques consolidées
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.modules.dashboard.service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", summary="Synthèse globale et KPIs multi-modules")
def get_dashboard_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    """
    Retourne la synthèse temps réel de l'état opérationnel Sentinelle AIOps :
    - KPIs généraux (indice de résilience, santé moyenne, alertes critiques)
    - Répartition de la santé du parc
    - Alertes actives récentes corrélées
    - Prédictions de panne les plus imminentes (TTF)
    - Journal des dernières actions d'audit
    - Statut des 4 modules spécialisés
    """
    return DashboardService.get_summary(db)
