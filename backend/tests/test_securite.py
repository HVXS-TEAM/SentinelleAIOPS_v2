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


def test_analyse_de_lot_ne_persiste_rien():
    """L'analyse d'un lot fourni détecte la force brute par règle statique et n'écrit rien en base."""
    db = SessionLocal()
    avant = (db.query(EvenementSecurite).count(), db.query(Alerte).count())
    logs = [f"Failed password for root from 198.51.100.99 port {4000 + i} ssh2" for i in range(6)]
    logs += ["Accepted password for sysadmin from 192.168.1.10 port 5001 ssh2", "ligne sans rapport"]
    res = SecurityService.train_and_detect_anomalies(db, logs)
    assert res["total_logs"] == len(logs)
    assert res["lignes_reconnues"] == 7
    assert res["anomalies_detectees"] == 1
    assert res["anomalies"][0]["type"] == "brute_force"
    assert res["anomalies"][0]["ip"] == "198.51.100.***"
    assert res["persiste"] is False
    assert (db.query(EvenementSecurite).count(), db.query(Alerte).count()) == avant
    db.close()


def test_api_securite_endpoints():
    """Endpoints REST : événements issus d'une vraie analyse, statistiques sans indicateur figé."""
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}
    db = SessionLocal()
    from backend.app.db.models import JournalAuthentification
    from backend.app.modules.securite import collectors
    lignes = [f"Failed password for root from 203.0.113.50 port {5000 + i} ssh2" for i in range(6)]
    SecurityService.ingest_events(db, [e for e in (collectors.parse_auth_line(l, origine="linux_authlog") for l in lignes) if e])
    SecurityService.analyze_window(db)
    db.close()

    resp_ev = client.get("/api/v1/securite/events?anomalies_only=true", headers=headers)
    assert resp_ev.status_code == 200
    assert any(e["source_ip_anonymisee"] == "203.0.113.***" for e in resp_ev.json())

    stats = client.get("/api/v1/securite/stats", headers=headers).json()
    assert stats["total_evenements"] > 0
    assert stats["total_anomalies"] >= 1
    assert "taux_precision_ia" not in stats and "baseline_accord_pct" not in stats
    assert stats["modele_actif"] in ("regles_statiques", "isolation_forest+regles_statiques")
    assert stats["echantillons_requis"] > 0
