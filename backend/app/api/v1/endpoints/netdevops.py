"""
Endpoints REST – Module NetDevOps (Audit CIS, Backup, Diff, Remédiation & Restauration).

Routes :
  GET  /netdevops/devices                → Liste des équipements disponibles
  POST /netdevops/audit/{device_id}      → Lance un audit CIS complet
  GET  /netdevops/backups/{device_id}    → Historique des sauvegardes
  GET  /netdevops/diff/{device_id}       → Diff entre deux sauvegardes
  POST /netdevops/remediate/{device_id}  → Applique une remédiation CIS réelle (SSH + DB)
  POST /netdevops/restore/{device_id}    → Restaure une sauvegarde de configuration
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from backend.app.modules.netdevops.service import (
    get_available_devices,
    get_config_diff,
    get_device_backups,
    remediate_device_config,
    restore_device_backup,
    run_audit,
)

router = APIRouter(prefix="/netdevops", tags=["NetDevOps"])


class RemediateRequest(BaseModel):
    """Requête d'application d'un correctif de configuration CIS."""

    remediation_snippet: str = Field(..., min_length=1, description="Bloc de commandes correctives CIS")
    rule_id: str | None = Field(default=None, description="Identifiant de la règle CIS corrigée")


class RestoreBackupRequest(BaseModel):
    """Requête de restauration d'une sauvegarde de configuration."""

    backup_index: int = Field(default=0, ge=0, description="Index de la sauvegarde à restaurer (0 = la plus récente)")


@router.get("/devices", summary="Liste des équipements disponibles")
def list_devices() -> list[dict]:
    """
    Rôle : Retourne tous les équipements réseau (base SQLite + parc inventorié) disponibles pour l'audit CIS.
    Entrées : Aucune.
    Sorties : Liste de dictionnaires équipements.
    """
    return get_available_devices()


@router.post("/audit/{device_id}", summary="Audit CIS Benchmark d'un équipement")
async def audit_device(device_id: str) -> dict:
    """
    Rôle : Lance un audit CIS Level 1 sur l'équipement spécifié.
    - Vérifie chaque règle CIS contre la configuration active (récupérée en SSH si joignable ou en base)
    - Calcule un score de conformité pondéré par sévérité
    - Sauvegarde automatiquement la config avec empreinte SHA-256 en SQLite
    - Génère des recommandations via Ollama (ou fallback local)
    Cas d'erreur : 404 si l'équipement est introuvable.
    """
    try:
        return await run_audit(device_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/backups/{device_id}", summary="Historique des sauvegardes de configuration")
def device_backups(device_id: str) -> list[dict]:
    """
    Rôle : Retourne la liste des sauvegardes de configuration disponibles pour un équipement.
    Entrées : device_id.
    Sorties : Liste des snapshots horodatés avec empreinte SHA-256.
    Cas d'erreur : 404 si l'équipement est inconnu.
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
    Rôle : Génère un diff unifié entre deux sauvegardes de configuration d'un équipement.
    - `index_b` (défaut 0) = sauvegarde la plus récente
    - `index_a` (défaut 1) = sauvegarde précédente
    Cas d'erreur : 404 si équipement inconnu, 422 si moins de 2 sauvegardes.
    """
    try:
        result = get_config_diff(device_id, index_a, index_b)
        if "error" in result:
            raise HTTPException(status_code=422, detail=result["error"])
        return result
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/remediate/{device_id}", summary="Application d'une remédiation CIS sur un équipement")
async def remediate_device(device_id: str, payload: RemediateRequest) -> dict:
    """
    Rôle : Applique un script de remédiation CIS sur l'équipement (via SSH si disponible + persistance SQLite),
    crée un snapshot de configuration SHA-256, recalcule le score CIS et retourne le diff unifié.
    Entrées : device_id, payload (remediation_snippet, rule_id).
    Sorties : Dictionnaire contenant le nouvel audit, le diff et le mode d'exécution.
    Cas d'erreur : 404 si l'équipement est introuvable.
    """
    try:
        return await remediate_device_config(
            device_id=device_id,
            remediation_commands=payload.remediation_snippet,
            finding_id=payload.rule_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/restore/{device_id}", summary="Restauration d'une sauvegarde de configuration")
async def restore_device_config(device_id: str, payload: RestoreBackupRequest) -> dict:
    """
    Rôle : Restaure une configuration antérieure sur un équipement à partir de son historique de sauvegardes.
    Entrées : device_id, payload (backup_index).
    Sorties : Dictionnaire avec statut de restauration et nouvel audit CIS.
    Cas d'erreur : 404 si équipement ou sauvegarde introuvable.
    """
    try:
        return await restore_device_backup(
            device_id=device_id,
            backup_index=payload.backup_index,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
