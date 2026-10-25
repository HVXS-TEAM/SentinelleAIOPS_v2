"""
Endpoints REST – Module NetDevOps (Audit CIS, Backup, Diff, Devices).

Routes :
  GET  /netdevops/devices               → Liste des équipements disponibles
  POST /netdevops/audit/{device_id}     → Lance un audit CIS complet
  GET  /netdevops/backups/{device_id}   → Historique des sauvegardes
  GET  /netdevops/diff/{device_id}      → Diff entre deux sauvegardes
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from backend.app.modules.netdevops.service import (
    get_available_devices,
    get_config_diff,
    get_device_backups,
    run_audit,
)

router = APIRouter(prefix="/netdevops", tags=["NetDevOps"])


@router.get("/devices", summary="Liste des équipements disponibles")
def list_devices() -> list[dict]:
    """Retourne tous les équipements Cisco IOS disponibles pour l'audit CIS."""
    return get_available_devices()


@router.post("/audit/{device_id}", summary="Audit CIS Benchmark d'un équipement")
async def audit_device(device_id: str) -> dict:
    """
    Lance un audit CIS Level 1 sur l'équipement spécifié.

    - Vérifie chaque règle CIS contre la configuration active
    - Calcule un score de conformité pondéré par sévérité
    - Sauvegarde automatiquement la config
    - Génère des recommandations via Ollama (ou fallback local)
    """
    try:
        return await run_audit(device_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/backups/{device_id}", summary="Historique des sauvegardes de configuration")
def device_backups(device_id: str) -> list[dict]:
    """
    Retourne la liste des sauvegardes de configuration disponibles pour un équipement.
    Chaque entrée contient un index et un timestamp.
    """
    try:
        return get_device_backups(device_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/diff/{device_id}", summary="Diff entre deux sauvegardes de configuration")
def config_diff(
    device_id: str,
    index_a: int = Query(default=1, ge=0, description="Index de la sauvegarde ancienne (0 = la plus récente)"),
    index_b: int = Query(default=0, ge=0, description="Index de la sauvegarde récente"),
) -> dict:
    """
    Génère un diff unifié entre deux sauvegardes de configuration d'un équipement.

    - `index_b` (défaut 0) = sauvegarde la plus récente
    - `index_a` (défaut 1) = sauvegarde précédente
    """
    try:
        result = get_config_diff(device_id, index_a, index_b)
        if "error" in result:
            raise HTTPException(status_code=422, detail=result["error"])
        return result
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
