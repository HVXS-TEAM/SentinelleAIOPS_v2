"""Tests unitaires et d'intégration du module Dashboard Global & Vue d'ensemble Opérationnelle."""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.db.session import SessionLocal
from backend.app.modules.dashboard.service import DashboardService

client = TestClient(app)


def test_dashboard_service_summary():
    """Vérifie la génération du résumé consolidé AIOps à partir de la base de données."""
    db = SessionLocal()
    try:
        summary = DashboardService.get_summary(db)
        assert "kpis" in summary
        assert "repartition_sante" in summary
        assert "alertes_recentes" in summary
        assert "predictions_critiques" in summary
        assert "activites_recentes" in summary
        assert "statut_modules" in summary

        # Vérification KPIs
        kpis = summary["kpis"]
        assert kpis["total_equipements"] >= 1
        assert 0.0 <= kpis["indice_resilience"] <= 100.0
        assert 0.0 <= kpis["sante_moyenne"] <= 100.0
        assert 0.0 <= kpis["cis_conformite_moyenne"] <= 100.0
        assert kpis["alertes_actives"] >= 0

        # Vérification répartition santé
        rep = summary["repartition_sante"]
        assert (rep["sain"] + rep["degrade"] + rep["critique"]) == kpis["total_equipements"]

        # Vérification modules actifs
        assert len(summary["statut_modules"]) == 4
        for mod in summary["statut_modules"]:
            assert mod["statut"] == "Opérationnel"
            assert mod["actif"] is True
    finally:
        db.close()


def test_api_dashboard_summary_endpoint():
    """Vérifie le point de terminaison REST /api/v1/dashboard/summary."""
    response = client.get("/api/v1/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert "kpis" in data
    assert "repartition_sante" in data
    assert "statut_modules" in data
    assert len(data["statut_modules"]) == 4
