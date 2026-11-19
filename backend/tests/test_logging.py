"""Journalisation et gestion des erreurs : plus aucune erreur avalée en silence, aucun secret dans les logs."""
import ast
import logging
from pathlib import Path

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from backend.app.core import config as cfg
from backend.app.core import logging_config
from backend.app.main import app

ROOT = Path(__file__).resolve().parents[2]
APP_DIR = ROOT / "backend" / "app"
client = TestClient(app)

LOG_METHODS = {"debug", "info", "warning", "error", "exception", "critical"}


# ── Garde-fou : aucun except large silencieux ────────────────────────────────

def _handler_journalise_ou_relance(handler: ast.ExceptHandler) -> bool:
    for node in ast.walk(handler):
        if isinstance(node, ast.Raise):
            return True
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in LOG_METHODS:
                return True
            if isinstance(f, ast.Name) and f.id == "log_connection_failure":
                return True
    return False


def test_aucun_except_large_silencieux():
    """Tout `except Exception` doit journaliser ou relancer : une erreur ne disparaît plus sans trace."""
    fautifs = []
    for p in sorted(APP_DIR.rglob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            large = node.type is None or (isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"))
            if large and not _handler_journalise_ou_relance(node):
                fautifs.append(f"{p.relative_to(ROOT)}:{node.lineno}")
    assert not fautifs, f"except large sans log ni raise : {fautifs}"


def test_pas_de_pass_apres_un_log_dans_les_handlers():
    """Un handler ne doit jamais se réduire à `pass` (journalisation ou traitement explicite requis)."""
    fautifs = []
    for p in sorted(APP_DIR.rglob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                large = node.type is None or (isinstance(node.type, ast.Name) and node.type.id == "Exception")
                if large:
                    fautifs.append(f"{p.relative_to(ROOT)}:{node.lineno}")
    assert not fautifs, fautifs


# ── Configuration des logs ───────────────────────────────────────────────────

@pytest.fixture()
def logs_isoles(monkeypatch, tmp_path):
    monkeypatch.setattr(cfg, "DATA_DIR", tmp_path)
    yield tmp_path
    logging_config.setup_logging()  # restaure la configuration par défaut


def test_setup_logging_cree_un_fichier_rotatif(logs_isoles):
    racine = logging_config.setup_logging("INFO")
    logging.getLogger("sentinelle.test").warning("message de test")
    for h in racine.handlers:
        h.flush()
    fichier = logs_isoles / "logs" / "sentinelle.log"
    assert fichier.exists() and "message de test" in fichier.read_text(encoding="utf-8")
    assert any(isinstance(h, logging.handlers.RotatingFileHandler) for h in racine.handlers)


def test_setup_logging_est_idempotent(logs_isoles):
    logging_config.setup_logging()
    n = len(logging.getLogger("sentinelle").handlers)
    logging_config.setup_logging()
    logging_config.setup_logging()
    assert len(logging.getLogger("sentinelle").handlers) == n


def test_niveau_de_log_configurable(logs_isoles):
    assert logging_config.setup_logging("DEBUG").level == logging.DEBUG
    assert logging_config.setup_logging("ERROR").level == logging.ERROR


def test_log_level_invalide_refuse(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "BAVARD")
    with pytest.raises(ValueError):
        cfg.Settings()


def test_log_level_accepte_la_casse(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "debug")
    assert cfg.Settings().LOG_LEVEL == "DEBUG"


# ── Erreur non gérée : réponse générique, trace dans les logs ───────────────

def test_erreur_interne_ne_fuit_rien_et_est_journalisee(caplog):
    routeur = APIRouter()

    @routeur.get("/__test_boom")
    def boom():
        raise RuntimeError("secret-interne-123")

    app.include_router(routeur)
    try:
        with caplog.at_level(logging.ERROR, logger="sentinelle"):
            resp = TestClient(app, raise_server_exceptions=False).get("/__test_boom")
    finally:
        app.router.routes[:] = [r for r in app.router.routes if getattr(r, "path", "") != "/__test_boom"]
    assert resp.status_code == 500
    corps = resp.json()
    assert corps["detail"] == "Erreur interne du serveur"
    assert "secret-interne-123" not in resp.text and "Traceback" not in resp.text
    assert corps["request_id"]
    journal = "\n".join(r.getMessage() + (r.exc_text or "") for r in caplog.records)
    assert corps["request_id"] in journal and "secret-interne-123" in journal  # détail seulement dans les logs


# ── Les erreurs métier laissent des traces ───────────────────────────────────

def test_echec_d_un_job_planifie_est_journalise(caplog, monkeypatch):
    from backend.app.core import scheduler
    from backend.app.modules.supervision.hardware_collector import HardwareCollector

    def casse(db):
        raise RuntimeError("collecte cassée")

    monkeypatch.setattr(HardwareCollector, "collect_live_metrics", staticmethod(casse))
    with caplog.at_level(logging.WARNING, logger="sentinelle"):
        scheduler._job_collect_host_metrics()
    assert any("collecte cassée" in r.getMessage() for r in caplog.records)


def test_sante_degradee_journalisee(caplog, monkeypatch):
    from backend.app import main

    class SessionCassee:
        def __enter__(self):
            raise RuntimeError("base injoignable")

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(main, "SessionLocal", SessionCassee)
    with caplog.at_level(logging.ERROR, logger="sentinelle"):
        resp = client.get("/api/v1/health")
    assert resp.status_code == 503
    assert any("base de données inaccessible" in r.getMessage() for r in caplog.records)


def test_echec_notification_ne_journalise_pas_le_secret(caplog, monkeypatch, admin_headers):
    """L'URL d'un webhook est un secret : elle ne doit jamais apparaître dans les logs."""
    from backend.app.modules.admin import notifications

    secret = "https://discord.com/api/webhooks/123/TOKEN-ULTRA-SECRET"

    class ClientCasse:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, *a, **k):
            raise RuntimeError(f"échec vers {url}")

    monkeypatch.setattr(notifications.httpx, "Client", ClientCasse)
    with caplog.at_level(logging.DEBUG, logger="sentinelle"):
        resp = client.post(
            "/api/v1/admin/notifications/test",
            headers=admin_headers,
            json={"channel": "discord", "discord_config": {"webhook_url": secret}, "message": "t"},
        )
    assert resp.status_code in (200, 422), resp.text
    assert "TOKEN-ULTRA-SECRET" not in "\n".join(r.getMessage() for r in caplog.records)

