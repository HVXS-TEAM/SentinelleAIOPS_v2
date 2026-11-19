"""Première configuration, politique de mot de passe, changement et réinitialisation."""
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import Settings
from backend.app.db.models import User
from backend.app.db.session import SessionLocal
from backend.app.main import app

client = TestClient(app)


def test_inscription_fermee_par_defaut():
    assert Settings.model_fields["ALLOW_SELF_REGISTRATION"].default is False


def test_setup_status_public_et_setup_refuse_si_comptes_existent():
    r = client.get("/api/v1/auth/setup-status")
    assert r.status_code == 200
    assert r.json()["needs_setup"] is False
    r = client.post("/api/v1/auth/setup", json={
        "identifiant": "pirate", "email": "p@x.fr", "nom_complet": "P", "mot_de_passe": "MotDePasse2026!"})
    assert r.status_code == 409


def test_premier_administrateur_cree_sur_base_vide():
    """Simule une base sans compte : le premier appel crée l'Administrateur, le second est refusé."""
    with SessionLocal() as db:
        sauvegarde = [
            dict(identifiant=u.identifiant, email=u.email, nom_complet=u.nom_complet,
                 hash_mot_de_passe=u.hash_mot_de_passe, role=u.role, est_actif=u.est_actif, mfa_active=u.mfa_active)
            for u in db.query(User).all()
        ]
    # NB : les journaux d'audit référencent les comptes ; on les détache le temps du test.
    from backend.app.db.models import JournalAudit
    try:
        with SessionLocal() as db:
            db.query(JournalAudit).update({JournalAudit.utilisateur_id: None})
            db.query(User).delete()
            db.commit()
        assert client.get("/api/v1/auth/setup-status").json()["needs_setup"] is True

        faible = client.post("/api/v1/auth/setup", json={
            "identifiant": "root", "email": "root@exemple.fr", "nom_complet": "Root", "mot_de_passe": "court1"})
        assert faible.status_code == 400

        ok = client.post("/api/v1/auth/setup", json={
            "identifiant": "root", "email": "root@exemple.fr", "nom_complet": "Root", "mot_de_passe": "MotDePasse2026!"})
        assert ok.status_code == 200, ok.text
        assert ok.json()["role"] == "Administrateur"
        h = {"Authorization": f"Bearer {ok.json()['access_token']}"}
        assert client.get("/api/v1/admin/users", headers=h).status_code == 200

        encore = client.post("/api/v1/auth/setup", json={
            "identifiant": "root2", "email": "r2@exemple.fr", "nom_complet": "R2", "mot_de_passe": "MotDePasse2026!"})
        assert encore.status_code == 409
    finally:
        with SessionLocal() as db:
            db.query(JournalAudit).update({JournalAudit.utilisateur_id: None})
            db.query(User).delete()
            for d in sauvegarde:
                db.add(User(**d))
            db.commit()


@pytest.mark.parametrize("mdp", ["Court1", "uniquementdeslettres", "123456789012"])
def test_politique_mot_de_passe_creation_admin(mdp, admin_headers):
    r = client.post("/api/v1/admin/users", headers=admin_headers, json={
        "identifiant": f"u_{uuid.uuid4().hex[:6]}", "email": f"{uuid.uuid4().hex[:6]}@x.fr",
        "nom_complet": "Test Politique", "mot_de_passe": mdp, "role": "Visiteur"})
    assert r.status_code in (400, 422)


def _creer_compte(admin_headers) -> tuple[int, str, str]:
    ident = f"pw_{uuid.uuid4().hex[:8]}"
    mdp = "AncienMotDePasse2026"
    r = client.post("/api/v1/admin/users", headers=admin_headers, json={
        "identifiant": ident, "email": f"{ident}@x.fr", "nom_complet": "Compte Mdp", "mot_de_passe": mdp, "role": "Technicien"})
    assert r.status_code == 200, r.text
    return r.json()["id"], ident, mdp


def _login(ident, mdp):
    return client.post("/api/v1/auth/login", json={"identifiant": ident, "mot_de_passe": mdp})


def test_changement_de_mot_de_passe(admin_headers):
    uid, ident, mdp = _creer_compte(admin_headers)
    h = {"Authorization": f"Bearer {_login(ident, mdp).json()['access_token']}"}
    nouveau = "NouveauMotDePasse2027"

    assert client.post("/api/v1/auth/change-password", headers=h, json={
        "mot_de_passe_actuel": "faux", "nouveau_mot_de_passe": nouveau}).status_code == 401
    assert client.post("/api/v1/auth/change-password", headers=h, json={
        "mot_de_passe_actuel": mdp, "nouveau_mot_de_passe": "court"}).status_code == 400
    assert client.post("/api/v1/auth/change-password", headers=h, json={
        "mot_de_passe_actuel": mdp, "nouveau_mot_de_passe": mdp}).status_code == 400
    assert client.post("/api/v1/auth/change-password", headers=h, json={
        "mot_de_passe_actuel": mdp, "nouveau_mot_de_passe": nouveau}).status_code == 200

    assert _login(ident, mdp).status_code == 401
    assert _login(ident, nouveau).status_code == 200
    assert client.post("/api/v1/auth/change-password", json={
        "mot_de_passe_actuel": mdp, "nouveau_mot_de_passe": nouveau}).status_code == 401


def test_reinitialisation_par_admin_leve_le_verrouillage(admin_headers, tech_headers):
    uid, ident, mdp = _creer_compte(admin_headers)
    for _ in range(5):
        _login(ident, "mauvais")
    assert _login(ident, mdp).status_code == 403  # verrouillé

    assert client.post(f"/api/v1/admin/users/{uid}/password", headers=tech_headers,
                       json={"nouveau_mot_de_passe": "ResetMotDePasse2027"}).status_code == 403
    assert client.post(f"/api/v1/admin/users/{uid}/password", headers=admin_headers,
                       json={"nouveau_mot_de_passe": "court"}).status_code == 400
    assert client.post("/api/v1/admin/users/999999/password", headers=admin_headers,
                       json={"nouveau_mot_de_passe": "ResetMotDePasse2027"}).status_code == 404
    assert client.post(f"/api/v1/admin/users/{uid}/password", headers=admin_headers,
                       json={"nouveau_mot_de_passe": "ResetMotDePasse2027"}).status_code == 200
    assert _login(ident, "ResetMotDePasse2027").status_code == 200
