"""Création de compte par profil (poste local), mot de passe oublié (e-mail ou code admin)."""
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.app.api.v1.endpoints import auth as auth_ep
from backend.app.core import emailing
from backend.app.core.config import settings
from backend.app.db.models import JetonReinitialisation, User
from backend.app.db.session import SessionLocal
from backend.app.main import app

client = TestClient(app)
MDP = "MotDePasse2026!"


def _compte(prefixe="cm"):
    ident = f"{prefixe}_{uuid.uuid4().hex[:8]}"
    return {"identifiant": ident, "email": f"{ident}@exemple.fr", "nom_complet": "Test Compte", "mot_de_passe": MDP}


@pytest.fixture
def nettoyage():
    crees = []
    yield crees
    with SessionLocal() as db:
        for ident in crees:
            u = db.query(User).filter(User.identifiant == ident).first()
            if u:
                db.query(JetonReinitialisation).filter(JetonReinitialisation.utilisateur_id == u.id).delete()
                db.delete(u)
        db.commit()


@pytest.fixture
def poste_local(monkeypatch):
    monkeypatch.setattr(auth_ep, "requete_locale", lambda request: True)


def _login(ident, mdp):
    return client.post("/api/v1/auth/login", json={"identifiant": ident, "mot_de_passe": mdp})


# ── Création de compte selon l'origine ────────────────────────────────────────

@pytest.mark.parametrize("role", ["Administrateur", "Technicien", "Visiteur"])
def test_poste_local_choisit_le_profil(poste_local, nettoyage, monkeypatch, role):
    monkeypatch.setattr(settings, "ALLOW_SELF_REGISTRATION", False)  # fermée au public, ouverte en local
    c = _compte()
    nettoyage.append(c["identifiant"])
    r = client.post("/api/v1/auth/register", json={**c, "role": role})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == role
    assert _login(c["identifiant"], MDP).json()["role"] == role


def test_poste_local_refuse_un_profil_inconnu(poste_local):
    r = client.post("/api/v1/auth/register", json={**_compte(), "role": "Root"})
    assert r.status_code == 400


def test_depuis_le_reseau_le_role_reste_visiteur(nettoyage):
    c = _compte()
    nettoyage.append(c["identifiant"])
    r = client.post("/api/v1/auth/register", json={**c, "role": "Administrateur"})
    assert r.status_code == 200 and r.json()["role"] == "Visiteur"


def test_reseau_ferme_refuse_meme_si_le_local_est_ouvert(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_SELF_REGISTRATION", False)
    assert client.post("/api/v1/auth/register", json={**_compte(), "role": "Administrateur"}).status_code == 403


@pytest.mark.parametrize("en_tete", ["x-forwarded-for", "forwarded", "x-real-ip"])
def test_un_proxy_annule_la_confiance_locale(en_tete):
    class Req:
        client = type("C", (), {"host": "127.0.0.1"})()
        headers = {en_tete: "203.0.113.9"}
    assert auth_ep.requete_locale(Req()) is False


def test_bouclage_sans_proxy_est_local_et_desactivable(monkeypatch):
    class Req:
        client = type("C", (), {"host": "127.0.0.1"})()
        headers = {}
    assert auth_ep.requete_locale(Req()) is True
    monkeypatch.setattr(settings, "LOCAL_ACCOUNT_CREATION", False)
    assert auth_ep.requete_locale(Req()) is False


def test_setup_status_expose_les_options(poste_local):
    j = client.get("/api/v1/auth/setup-status").json()
    assert j["local_creation"] is True
    assert j["roles_disponibles"] == ["Administrateur", "Technicien", "Visiteur"]
    assert j["smtp_configure"] is False


def test_setup_status_reseau_ne_propose_que_visiteur():
    assert client.get("/api/v1/auth/setup-status").json()["roles_disponibles"] == ["Visiteur"]


@pytest.fixture
def base_vide():
    """Poste neuf : base SQLite en mémoire sans aucun compte, substituée à la base de test."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from backend.app.db.session import Base, get_db
    moteur = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=moteur)
    Session = sessionmaker(bind=moteur)

    def _db():
        db = Session()
        try:
            yield db
        finally:
            db.close()
    app.dependency_overrides[get_db] = _db
    yield
    app.dependency_overrides.pop(get_db, None)


@pytest.mark.parametrize("role", ["Administrateur", "Technicien", "Visiteur"])
def test_poste_neuf_le_premier_compte_prend_le_profil_choisi(base_vide, role):
    assert client.get("/api/v1/auth/setup-status").json()["needs_setup"] is True
    r = client.post("/api/v1/auth/setup", json={**_compte("setup"), "role": role})
    assert r.status_code == 200 and r.json()["role"] == role
    assert client.get("/api/v1/auth/setup-status").json()["needs_setup"] is False
    # la configuration initiale ne peut plus être refaite
    assert client.post("/api/v1/auth/setup", json={**_compte("setup2"), "role": "Administrateur"}).status_code == 409


def test_poste_neuf_refuse_un_profil_inconnu(base_vide):
    assert client.post("/api/v1/auth/setup", json={**_compte("setup"), "role": "Root"}).status_code == 400


def test_poste_neuf_sans_profil_reste_administrateur(base_vide):
    c = _compte("setup")
    r = client.post("/api/v1/auth/setup", json={k: c[k] for k in ("identifiant", "email", "nom_complet", "mot_de_passe")})
    assert r.status_code == 200 and r.json()["role"] == "Administrateur"


# ── Mot de passe oublié ───────────────────────────────────────────────────────

def test_oubli_sans_smtp_renvoie_le_mode_code_admin():
    r = client.post("/api/v1/auth/forgot-password", json={"identifiant": "admin"})
    assert r.status_code == 200 and r.json()["mode"] == "admin_code"


def test_code_admin_de_bout_en_bout(admin_headers, nettoyage):
    c = _compte()
    nettoyage.append(c["identifiant"])
    client.post("/api/v1/admin/users", headers=admin_headers, json={**c, "role": "Technicien"})
    uid = next(u["id"] for u in client.get("/api/v1/admin/users", headers=admin_headers).json()
               if u["identifiant"] == c["identifiant"])
    r = client.post(f"/api/v1/admin/users/{uid}/reset-code", headers=admin_headers)
    assert r.status_code == 200
    code = r.json()["code"]
    assert len(code) == 11 and code[5] == "-"
    nouveau = "NouveauMdp2026ok"
    # un mauvais code est refusé, le bon fonctionne (casse et tiret tolérés)
    assert client.post("/api/v1/auth/reset-password", json={"identifiant": c["identifiant"], "code": "AAAAA-AAAAA", "nouveau_mot_de_passe": nouveau}).status_code == 400
    ok = client.post("/api/v1/auth/reset-password", json={"identifiant": c["identifiant"], "code": code.lower().replace("-", ""), "nouveau_mot_de_passe": nouveau})
    assert ok.status_code == 200
    assert _login(c["identifiant"], nouveau).status_code == 200
    assert _login(c["identifiant"], MDP).status_code == 401
    # usage unique
    assert client.post("/api/v1/auth/reset-password", json={"identifiant": c["identifiant"], "code": code, "nouveau_mot_de_passe": "Encore2026Mdpok"}).status_code == 400


def test_reset_code_reserve_a_l_administrateur(tech_headers):
    assert client.post("/api/v1/admin/users/1/reset-code", headers=tech_headers).status_code == 403
    assert client.post("/api/v1/admin/users/1/reset-code").status_code in (401, 403)


def test_code_bloque_apres_cinq_essais(admin_headers, nettoyage):
    c = _compte()
    nettoyage.append(c["identifiant"])
    client.post("/api/v1/admin/users", headers=admin_headers, json={**c, "role": "Visiteur"})
    uid = next(u["id"] for u in client.get("/api/v1/admin/users", headers=admin_headers).json() if u["identifiant"] == c["identifiant"])
    code = client.post(f"/api/v1/admin/users/{uid}/reset-code", headers=admin_headers).json()["code"]
    for _ in range(5):
        client.post("/api/v1/auth/reset-password", json={"identifiant": c["identifiant"], "code": "ZZZZZ-ZZZZZ", "nouveau_mot_de_passe": "Nouveau2026Mdpok"})
    # même le bon code est désormais refusé : il faut en demander un autre
    assert client.post("/api/v1/auth/reset-password", json={"identifiant": c["identifiant"], "code": code, "nouveau_mot_de_passe": "Nouveau2026Mdpok"}).status_code == 400


def test_nouveau_code_invalide_le_precedent(admin_headers, nettoyage):
    c = _compte()
    nettoyage.append(c["identifiant"])
    client.post("/api/v1/admin/users", headers=admin_headers, json={**c, "role": "Visiteur"})
    uid = next(u["id"] for u in client.get("/api/v1/admin/users", headers=admin_headers).json() if u["identifiant"] == c["identifiant"])
    ancien = client.post(f"/api/v1/admin/users/{uid}/reset-code", headers=admin_headers).json()["code"]
    client.post(f"/api/v1/admin/users/{uid}/reset-code", headers=admin_headers)
    assert client.post("/api/v1/auth/reset-password", json={"identifiant": c["identifiant"], "code": ancien, "nouveau_mot_de_passe": "Nouveau2026Mdpok"}).status_code == 400


def test_mot_de_passe_trop_faible_refuse_a_la_reinitialisation():
    assert client.post("/api/v1/auth/reset-password", json={"identifiant": "admin", "code": "AAAAA-AAAAA", "nouveau_mot_de_passe": "court"}).status_code in (400,)


def test_oubli_par_email_envoie_un_lien_et_ne_revele_rien(monkeypatch, admin_headers, nettoyage):
    envoyes = []
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_FROM", "sentinelle@test")
    monkeypatch.setattr(emailing, "envoyer", lambda dest, sujet, corps: envoyes.append((dest, corps)))
    c = _compte()
    nettoyage.append(c["identifiant"])
    client.post("/api/v1/admin/users", headers=admin_headers, json={**c, "role": "Visiteur"})
    r1 = client.post("/api/v1/auth/forgot-password", json={"identifiant": c["identifiant"]})
    r2 = client.post("/api/v1/auth/forgot-password", json={"identifiant": "compte_qui_n_existe_pas"})
    assert r1.json() == r2.json() and r1.json()["mode"] == "email"  # même réponse : pas d'énumération
    assert len(envoyes) == 1 and envoyes[0][0] == c["email"]
    jeton = envoyes[0][1].split("?reset=")[1].split("&")[0]
    nouveau = "ViaEmail2026Mdpok"
    assert client.post("/api/v1/auth/reset-password", json={"identifiant": c["identifiant"], "code": jeton, "nouveau_mot_de_passe": nouveau}).status_code == 200
    assert _login(c["identifiant"], nouveau).status_code == 200


def test_demandes_rapprochees_n_envoient_qu_un_email(monkeypatch, admin_headers, nettoyage):
    envoyes = []
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_FROM", "sentinelle@test")
    monkeypatch.setattr(emailing, "envoyer", lambda dest, sujet, corps: envoyes.append(dest))
    c = _compte()
    nettoyage.append(c["identifiant"])
    client.post("/api/v1/admin/users", headers=admin_headers, json={**c, "role": "Visiteur"})
    for _ in range(3):
        client.post("/api/v1/auth/forgot-password", json={"identifiant": c["identifiant"]})
    assert len(envoyes) == 1


def test_echec_smtp_ne_change_pas_la_reponse(monkeypatch, admin_headers, nettoyage):
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.test")
    monkeypatch.setattr(settings, "SMTP_FROM", "sentinelle@test")
    def echec(*a):
        raise emailing.EmailError("SMTPException")
    monkeypatch.setattr(emailing, "envoyer", echec)
    c = _compte()
    nettoyage.append(c["identifiant"])
    client.post("/api/v1/admin/users", headers=admin_headers, json={**c, "role": "Visiteur"})
    r = client.post("/api/v1/auth/forgot-password", json={"identifiant": c["identifiant"]})
    assert r.status_code == 200 and r.json()["mode"] == "email"


def test_jeton_expire_refuse(admin_headers, nettoyage):
    from datetime import timedelta
    c = _compte()
    nettoyage.append(c["identifiant"])
    client.post("/api/v1/admin/users", headers=admin_headers, json={**c, "role": "Visiteur"})
    uid = next(u["id"] for u in client.get("/api/v1/admin/users", headers=admin_headers).json() if u["identifiant"] == c["identifiant"])
    code = client.post(f"/api/v1/admin/users/{uid}/reset-code", headers=admin_headers).json()["code"]
    with SessionLocal() as db:
        for j in db.query(JetonReinitialisation).filter(JetonReinitialisation.utilisateur_id == uid):
            j.expire_le = j.expire_le - timedelta(hours=2)
        db.commit()
    assert client.post("/api/v1/auth/reset-password", json={"identifiant": c["identifiant"], "code": code, "nouveau_mot_de_passe": "Nouveau2026Mdpok"}).status_code == 400


def test_seule_l_empreinte_est_stockee(admin_headers, nettoyage):
    c = _compte()
    nettoyage.append(c["identifiant"])
    client.post("/api/v1/admin/users", headers=admin_headers, json={**c, "role": "Visiteur"})
    uid = next(u["id"] for u in client.get("/api/v1/admin/users", headers=admin_headers).json() if u["identifiant"] == c["identifiant"])
    code = client.post(f"/api/v1/admin/users/{uid}/reset-code", headers=admin_headers).json()["code"]
    with SessionLocal() as db:
        j = db.query(JetonReinitialisation).filter(JetonReinitialisation.utilisateur_id == uid).first()
        assert len(j.empreinte) == 64 and code.replace("-", "") not in j.empreinte and code not in j.empreinte
