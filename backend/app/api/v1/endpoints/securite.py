"""Endpoints de l'API de Cybersécurité, Détection d'Anomalies (Isolation Forest) et Pare-feu Actif."""
from datetime import datetime, timedelta, timezone
from typing import List
import socket
try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.core.config import settings
from backend.app.db.models import EvenementSecurite, JournalAuthentification, User, Equipement
from backend.app.schemas.securite import (
    EvenementSecuriteOut,
    AnalyzeBatchRequest,
    BlockIpRequest,
    IsolateDeviceRequest,
    SecurityStatsResponse,
)
from backend.app.modules.securite.service import SecurityService
from backend.app.modules.securite.syslog_receiver import get_receiver
from sqlalchemy import func
from backend.app.api.deps import get_current_user, require_roles

import logging
logger = logging.getLogger("sentinelle.api.securite")


router = APIRouter(prefix="/securite", tags=["Cybersécurité & Détection d'Anomalies (IA)"])


@router.get("/events", response_model=List[EvenementSecuriteOut], summary="Journal des événements de sécurité")
def list_security_events(
    anomalies_only: bool = Query(default=True, description="Filtrer uniquement les anomalies détectées"),
    limit: int = Query(default=50, ge=5, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Rôle : Retourne la liste des événements analysés avec leurs scores d'anomalie et adresses IP anonymisées (RGPD).
    Entrées : Booléen anomalies_only, limite, session DB, utilisateur authentifié.
    Sorties : Liste d'EvenementSecuriteOut.
    """
    query = db.query(EvenementSecurite)
    if anomalies_only:
        query = query.filter(EvenementSecurite.is_anomaly.is_(True))
    return query.order_by(EvenementSecurite.horodatage.desc()).limit(limit).all()


@router.get("/stats", response_model=SecurityStatsResponse, summary="Statistiques globales de détection et sockets")
def get_security_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Rôle : Calcule les métriques de performance du modèle Isolation Forest et inspecte les sockets actifs de l'hôte.
    Entrées : Session DB, utilisateur authentifié.
    Sorties : Objet SecurityStatsResponse.
    """
    total = db.query(JournalAuthentification).count()
    anomalies = db.query(EvenementSecurite).filter(EvenementSecurite.is_anomaly.is_(True)).count()
    critiques = (
        db.query(EvenementSecurite)
        .filter(EvenementSecurite.is_anomaly.is_(True), EvenementSecurite.severite == "CRITICAL")
        .count()
    )
    bloquees = db.query(EvenementSecurite).filter(EvenementSecurite.explication.like("[BLOQUÉ]%")).count()
    par_source = dict(
        db.query(JournalAuthentification.origine, func.count(JournalAuthentification.id))
        .group_by(JournalAuthentification.origine).all()
    )
    derniere = db.query(func.max(JournalAuthentification.horodatage)).scalar()
    echantillons = int(len(SecurityService._matrice_reference(
        db, datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=settings.SECURITY_WINDOW_MINUTES),
        settings.SECURITY_WINDOW_MINUTES)))
    actif = echantillons >= settings.SECURITY_MIN_BASELINE_SAMPLES

    active_conns = 0
    listen_ports = 0
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == "LISTEN":
                listen_ports += 1
            elif c.raddr:
                active_conns += 1
    except Exception as exc:
        logger.debug("get_security_stats : repli après erreur : %s", exc)

    rec = get_receiver()
    return {
        "total_evenements": total,
        "total_anomalies": anomalies,
        "attaques_critiques": critiques,
        "ips_bloquees": bloquees,
        "modele_actif": "isolation_forest+regles_statiques" if actif else "regles_statiques",
        "echantillons_baseline": echantillons,
        "echantillons_requis": settings.SECURITY_MIN_BASELINE_SAMPLES,
        "evenements_par_source": par_source,
        "derniere_observation": derniere,
        "syslog_actif": rec is not None,
        "syslog_datagrammes_recus": rec.recus if rec else 0,
        "syslog_ignores_source_inconnue": rec.ignores_source_inconnue if rec else 0,
        "connexions_actives_hote": active_conns,
        "ports_ecoute_hote": listen_ports,
    }


@router.post("/scan-real", summary="Lecture et analyse des journaux d'authentification réels de l'hôte")
def run_real_security_scan_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """
    Rôle : Lit le journal d'authentification de l'hôte (Windows Security 4625/4624, auth.log ou journald),
           l'enregistre, puis détecte les anomalies. Les sources illisibles sont signalées dans `sources`.
    Entrées : Session DB, utilisateur authentifié.
    Sorties : Rapport de scan complet.
    """
    return SecurityService.run_real_security_scan(db)


@router.post("/block-ip", summary="Bloquer une adresse IP malveillante via le Pare-feu")
def block_ip_endpoint(
    req: BlockIpRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """
    Rôle : Applique une règle de blocage d'adresse IP (Pare-feu Windows netsh + base SQLite) et acquitte l'alerte.
    Entrées : Payload BlockIpRequest, session DB, utilisateur authentifié.
    Sorties : Confirmation de la règle pare-feu appliquée.
    """
    try:
        res = SecurityService.block_ip_address(
            db=db,
            source_ip=req.source_ip,
            incident_id=req.incident_id,
            equipement_id=req.equipement_id,
            motif=req.motif or "Blocage manuel opérateur SOC",
            user=current_user,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if res["status"] != "BLOCKED":
        raise HTTPException(status_code=409, detail=res["message"])
    return res


@router.post("/isolate-device", summary="Isoler un équipement en quarantaine réseau")
def isolate_device_endpoint(
    req: IsolateDeviceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """
    Rôle : Place un équipement compromis en quarantaine réseau et consigne l'opération dans le journal d'audit.
    Entrées : Payload IsolateDeviceRequest, session DB, utilisateur authentifié.
    Sorties : Confirmation d'isolement.
    """
    return SecurityService.isolate_device(
        db=db,
        device_name=req.device_name,
        equipement_id=req.equipement_id,
        motif=req.motif or "Isolement préventif SOC",
        user=current_user,
    )


@router.post("/analyze-batch", summary="Analyse d'un lot de logs fourni (sans enregistrement)")
def analyze_log_batch(
    req: AnalyzeBatchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["Administrateur", "Technicien"])),
):
    """Analyse des lignes sshd / Cisco IOS fournies ; rien n'est enregistré en base."""
    return SecurityService.train_and_detect_anomalies(
        db=db,
        log_batch=req.logs,
        equipement_id=req.equipement_id,
    )

