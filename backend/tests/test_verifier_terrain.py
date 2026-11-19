"""L'outil scripts/verifier_terrain.py : verdicts honnêtes face à l'API réelle (TestClient)."""
import importlib.util
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app

SPEC = importlib.util.spec_from_file_location(
    "verifier_terrain", Path(__file__).resolve().parents[2] / "scripts" / "verifier_terrain.py")
vt = importlib.util.module_from_spec(SPEC)
sys.modules["verifier_terrain"] = vt  # requis par @dataclass
SPEC.loader.exec_module(vt)

client = TestClient(app)


def _requeteur(methode, chemin, corps, jeton):
    r = client.request(methode, chemin, json=corps, headers={"Authorization": f"Bearer {jeton}"} if jeton else None)
    return r.status_code, (r.json() if r.content else None)


def test_connexion_refusee_arrete_la_verification():
    res, connecte = vt.verifier(_requeteur, "admin", "mauvais-mot-de-passe")
    assert connecte is False
    assert [r.nom for r in res] == ["Santé du serveur", "Connexion"]
    assert res[-1].statut == vt.ECHEC


def test_verification_complete_ne_masque_aucun_echec(monkeypatch):
    from backend.app.modules.securite import collectors
    monkeypatch.setattr(collectors, "collecter_hote", lambda: (
        [], [{"source": "/var/log/auth.log", "lisible": False, "detail": "illisible : Permission denied", "evenements_lus": 0}]))
    res, connecte = vt.verifier(_requeteur, "admin", "AdminPassword2026!")
    assert connecte is True
    par_nom = {r.nom: r for r in res}
    assert par_nom["Santé du serveur"].statut == vt.OK and par_nom["Connexion"].statut == vt.OK
    assert par_nom["Source /var/log/auth.log"].statut == vt.ECHEC  # journal illisible : jamais « OK »
    assert par_nom["Analyse de sécurité"].statut == vt.ECHEC
    assert par_nom["Récepteur syslog"].statut == vt.INFO
    assert any(r.nom.startswith("Sonde SW-CORE-01") for r in res)  # une sonde par équipement du parc
    assert any(r.nom.startswith("Découverte de") for r in res)


def test_serveur_injoignable_code_de_sortie_2(capsys, monkeypatch):
    monkeypatch.setenv("SENTINELLE_PASSWORD", "x")
    assert vt.main(["--url", "http://127.0.0.1:9", "--user", "admin"]) == 2
    assert "injoignable" in capsys.readouterr().err
