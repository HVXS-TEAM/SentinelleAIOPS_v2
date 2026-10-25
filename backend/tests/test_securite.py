"""Tests unitaires et d'intégration du module Cybersécurité & Détection d'anomalies (Isolation Forest)."""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.db.session import SessionLocal
from backend.app.db.models import Equipement, EvenementSecurite, Alerte
from backend.app.modules.securite.service import SecurityService, anonymize_ip_rgpd

client = TestClient(app)


def get_auth_token(identifiant: str = "admin", mot_de_passe: str = "AdminPassword2026!") -> str:
    resp = client.post("/api/v1/auth/login", json={"identifiant": identifiant, "mot_de_passe": mot_de_passe})
    return resp.json()["access_token"]


def test_log_parsing():
    """Vérifie l'extraction regex des paramètres clés des logs SSH."""
    line_failed = "Failed password for invalid user hacker from 203.0.113.195 port 49152 ssh2"
    parsed_fail = SecurityService.parse_log_line(line_failed)
    assert parsed_fail is not None
    assert parsed_fail["user"] == "hacker"
    assert parsed_fail["ip"] == "203.0.113.195"
    assert parsed_fail["is_failed"] == 1
    assert parsed_fail["is_invalid_user"] == 1

    line_ok = "Accepted password for debian from 192.168.1.100 port 52341 ssh2"
    parsed_ok = SecurityService.parse_log_line(line_ok)
    assert parsed_ok is not None
    assert parsed_ok["user"] == "debian"
    assert parsed_ok["is_failed"] == 0


def test_rgpd_ip_anonymization():
    """Vérifie le masquage systématique des adresses IP pour conformité RGPD."""
    assert anonymize_ip_rgpd("192.168.1.45") == "192.168.1.***"
    assert anonymize_ip_rgpd("10.0.0.1") == "10.0.0.***"


def test_isolation_forest_detection_and_baseline_comparison():
    """Vérifie l'entraînement de l'Isolation Forest et la détection d'anomalies face à la baseline."""
    db = SessionLocal()
    sample_logs = [
        # Attaque 1 : 6 échecs consécutifs
        "Failed password for invalid user admin from 198.51.100.99 port 4001 ssh2",
        "Failed password for invalid user test from 198.51.100.99 port 4002 ssh2",
        "Failed password for root from 198.51.100.99 port 4003 ssh2",
        "Failed password for root from 198.51.100.99 port 4004 ssh2",
        "Failed password for debian from 198.51.100.99 port 4005 ssh2",
        "Failed password for debian from 198.51.100.99 port 4006 ssh2",
        # Trafic normal : connexions acceptées
        "Accepted password for sysadmin from 192.168.1.10 port 5001 ssh2",
        "Accepted password for deploy from 192.168.1.11 port 5002 ssh2",
        "Accepted password for dev from 192.168.1.12 port 5003 ssh2",
        "Accepted password for dev from 192.168.1.12 port 5004 ssh2",
    ]

    res = SecurityService.train_and_detect_anomalies(db, sample_logs)
    assert res["total_logs"] == len(sample_logs)
    assert res["anomalies_detectees"] >= 1
    assert "comparaison_baseline" in res
    assert res["comparaison_baseline"]["accord_pourcentage"] >= 80.0
    db.close()


def test_simulate_bruteforce_and_correlation():
    """Vérifie l'injection d'attaque brute-force et la corrélation multi-modules avec la charge CPU."""
    db = SessionLocal()
    srv = db.query(Equipement).filter(Equipement.nom == "SRV-APP-01").first()
    assert srv is not None

    result = SecurityService.simulate_bruteforce_attack(
        db,
        equipement_id=srv.id,
        attacker_ip="198.51.100.77",
        target_server_name=srv.nom,
    )
    assert result["anomalies_detectees"] >= 1

    # Vérification de l'alerte de corrélation
    alert_corr = (
        db.query(Alerte)
        .filter(
            Alerte.equipement_id == srv.id,
            Alerte.correlation_id.isnot(None),
        )
        .order_by(Alerte.date_creation.desc())
        .first()
    )
    assert alert_corr is not None
    assert "Corrélation" in alert_corr.titre
    assert "198.51.100.***" in alert_corr.message
    db.close()


def test_api_securite_endpoints():
    """Vérifie les endpoints REST de sécurité et de statistiques."""
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    # Événements
    resp_ev = client.get("/api/v1/securite/events?anomalies_only=true", headers=headers)
    assert resp_ev.status_code == 200
    events = resp_ev.json()
    assert len(events) >= 1

    # Statistiques
    resp_stats = client.get("/api/v1/securite/stats", headers=headers)
    assert resp_stats.status_code == 200
    stats = resp_stats.json()
    assert stats["total_evenements"] > 0
    assert stats["taux_precision_ia"] > 90.0
