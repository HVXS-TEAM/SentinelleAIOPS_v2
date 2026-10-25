"""Tests unitaires et d'intégration du module Supervision Prédictive (TTF, régression, alertes)."""
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.db.session import SessionLocal
from backend.app.db.models import Equipement, Metrique, Alerte, Prediction
from backend.app.modules.supervision.service import SupervisionService, calculate_mape, evaluate_confidence

client = TestClient(app)


def get_auth_token(identifiant: str = "admin", mot_de_passe: str = "AdminPassword2026!") -> str:
    """Récupère un jeton JWT valide pour les tests d'API."""
    resp = client.post("/api/v1/auth/login", json={"identifiant": identifiant, "mot_de_passe": mot_de_passe})
    return resp.json()["access_token"]


def test_mape_and_confidence():
    """Valide les calculs d'erreurs et de niveau de confiance."""
    import numpy as np
    y_true = np.array([50.0, 60.0, 70.0])
    y_pred = np.array([51.0, 59.0, 70.0])
    mape = calculate_mape(y_true, y_pred)
    assert 0.0 < mape < 5.0

    assert evaluate_confidence(data_points_count=4, r2_score=0.95) == "Faible"
    assert evaluate_confidence(data_points_count=8, r2_score=0.75) == "Moyenne"
    assert evaluate_confidence(data_points_count=20, r2_score=0.92) == "Haute"


def test_record_metric_and_ttf_calculation():
    """Vérifie l'enregistrement d'une métrique et l'ajustement du modèle de régression."""
    db = SessionLocal()
    srv = db.query(Equipement).filter(Equipement.nom == "SRV-APP-01").first()
    assert srv is not None

    # Enregistrement métrique
    metric = SupervisionService.record_metric(db, srv.id, "disk_percent", 85.0)
    assert metric.valeur == 85.0
    assert srv.statut_collecte == "OK"

    # Calcul TTF
    pred = SupervisionService.calculate_ttf(db, srv.id, "disk_percent")
    assert pred is not None
    assert pred.pente_horaire > 0
    assert pred.ttf_estime_heures is not None
    assert pred.r2_score >= 0.0
    db.close()


def test_collection_failure_handling():
    """Vérifie la bascule en 'Injoignable' et la levée d'alerte lors d'une panne de sonde."""
    db = SessionLocal()
    srv = db.query(Equipement).filter(Equipement.nom == "SRV-DB-01").first()
    SupervisionService.record_collection_failure(db, srv.id, motif="Timeout agent SSH")
    
    assert srv.statut_collecte == "Injoignable"
    alert = db.query(Alerte).filter(Alerte.equipement_id == srv.id, Alerte.statut == "Active").first()
    assert alert is not None
    assert "Injoignable" in alert.message
    db.close()


def test_api_metrics_and_predictions_endpoints():
    """Vérifie les endpoints REST de métrologie et prédictions."""
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    srv = db.query(Equipement).filter(Equipement.nom == "SRV-APP-01").first()
    db.close()

    # 1. Obtenir la série de métriques
    resp_metrics = client.get(f"/api/v1/supervision/metrics/{srv.id}?type_metrique=disk_percent", headers=headers)
    assert resp_metrics.status_code == 200
    data = resp_metrics.json()
    assert len(data["points"]) > 0

    # 2. Obtenir les prédictions
    resp_pred = client.get("/api/v1/supervision/predictions", headers=headers)
    assert resp_pred.status_code == 200
    preds = resp_pred.json()
    assert len(preds) > 0


def test_api_simulation_stress_demo():
    """Vérifie le déclenchement en 1 clic de la simulation de stress disque pour la soutenance."""
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    db = SessionLocal()
    srv = db.query(Equipement).filter(Equipement.nom == "SRV-APP-01").first()
    db.close()

    resp_sim = client.post(
        "/api/v1/supervision/simulate-stress",
        json={"equipement_id": srv.id, "target_disk_percent": 91.5, "slope_boost": 3.0},
        headers=headers,
    )
    assert resp_sim.status_code == 200
    sim_data = resp_sim.json()
    assert sim_data["valeur_actuelle"] >= 90.0
    assert sim_data["ttf_estime_heures"] is not None


def test_hardware_collector_service():
    """Valide la collecte de télémétrie matérielle réelle avec psutil sur l'hôte."""
    from backend.app.modules.supervision.hardware_collector import HardwareCollector

    db = SessionLocal()
    try:
        metrics = HardwareCollector.collect_live_metrics(db)
        assert "cpu_percent" in metrics
        assert "ram_percent" in metrics
        assert "disk_percent" in metrics
        assert "hostname" in metrics
        assert "uptime_secondes" in metrics
        assert metrics["cpu_percent"] >= 0.0
        assert metrics["ram_percent"] >= 0.0
        assert metrics["disk_percent"] >= 0.0
        assert metrics["score_sante"] >= 10.0
        # Vérifie la présence de l'équipement dans la base
        eq = db.query(Equipement).filter(Equipement.id == metrics["equipement_id"]).first()
        assert eq is not None
        assert eq.groupe == "Hôte Local (Hardware)"
    finally:
        db.close()


def test_api_hardware_live_endpoint():
    """Vérifie l'endpoint API GET /api/v1/supervision/hardware/live."""
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/supervision/hardware/live", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "cpu_percent" in data
    assert "ram_percent" in data
    assert "disk_percent" in data
    assert "hostname" in data
    assert data["hostname"] != ""

