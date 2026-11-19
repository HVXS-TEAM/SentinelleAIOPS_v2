"""Second facteur TOTP : enrôlement, connexion en deux étapes, anti-rejeu, secours, verrouillage."""
import time
import uuid

import pyotp
import pytest
from fastapi.testclient import TestClient

from backend.app.core import mfa
from backend.app.core.security import get_password_hash
from backend.app.db.models import JournalAudit, User
from backend.app.db.session import SessionLocal
from backend.app.main import app

client = TestClient(app)
MDP = "MotDePasse2026!"


@pytest.fixture()
def compte():
    """Compte Technicien jetable (les comptes démo ne sont jamais modifiés)."""
    ident = f"mfa_{uuid.uuid4().hex[:8]}"
    with SessionLocal() as db:
        u = User(identifiant=ident, email=f"{ident}@sentinelle.local", nom_complet="Test MFA",
                 hash_mot_de_passe=get_password_hash(MDP), role="Technicien", est_actif=True, mfa_active=False)
        db.add(u)
        db.commit()
        uid = u.id
    yield ident
    with SessionLocal() as db:
        db.query(JournalAudit).filter(JournalAudit.utilisateur_id == uid).delete()
        db.query(User).filter(User.id == uid).delete()
        db.commit()


def _login(ident, code=None, mdp=MDP):
    body = {"identifiant": ident, "mot_de_passe": mdp}
    if code is not None:
        body["code_mfa"] = code
    return client.post("/api/v1/auth/login", json=body)


def _headers(ident):
    return {"Authorization": f"Bearer {_login(ident).json()['access_token']}"}


def _code_invalide(secret):
    """Un code à 6 chiffres qui n'est valide dans aucune fenêtre voisine."""
    totp = pyotp.TOTP(secret)
    valides = {totp.at(time.time() + d * 30) for d in (-3, -2, -1, 0, 1, 2, 3)}
    return next(c for c in ("000000", "111111", "222222", "333333") if c not in valides)


def _activer(ident):
    h = _headers(ident)
    secret = client.post("/api/v1/auth/mfa/setup", headers=h).json()["secret"]
    r = client.post("/api/v1/auth/mfa/enable", headers=h, json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    return secret, r.json()["recovery_codes"]


def _code_suivant(secret):
    """Code du pas suivant : valide (fenêtre ±1) et postérieur au pas consommé par l'activation."""
    return pyotp.TOTP(secret).at(time.time() + 30)


# ── Enrôlement ───────────────────────────────────────────────────────────────

def test_setup_renvoie_secret_et_uri_sans_activer(compte):
    r = client.post("/api/v1/auth/mfa/setup", headers=_headers(compte))
    assert r.status_code == 200
    data = r.json()
    assert data["otpauth_uri"].startswith("otpauth://totp/")
    assert "Sentinelle" in data["otpauth_uri"] and data["secret"] in data["otpauth_uri"]
    assert _login(compte).status_code == 200  # pas encore exigé


def test_secret_chiffre_en_base(compte):
    secret, _ = _activer(compte)
    with SessionLocal() as db:
        u = db.query(User).filter(User.identifiant == compte).one()
        assert u.mfa_active is True
        assert secret not in u.mfa_secret


def test_enable_sans_setup_refuse(compte):
    r = client.post("/api/v1/auth/mfa/enable", headers=_headers(compte), json={"code": "123456"})
    assert r.status_code == 400


def test_enable_mauvais_code_ne_active_pas(compte):
    h = _headers(compte)
    secret = client.post("/api/v1/auth/mfa/setup", headers=h).json()["secret"]
    r = client.post("/api/v1/auth/mfa/enable", headers=h, json={"code": _code_invalide(secret)})
    assert r.status_code == 400
    assert _login(compte).status_code == 200


def test_enable_retourne_huit_codes_de_secours(compte):
    _, codes = _activer(compte)
    assert len(codes) == 8 and len(set(codes)) == 8


def test_setup_refuse_si_deja_actif(compte):
    _activer(compte)
    r = client.post("/api/v1/auth/mfa/setup", headers=_headers_apres_mfa(compte))
    assert r.status_code == 400


def _headers_apres_mfa(ident):
    r = None
    with SessionLocal() as db:
        u = db.query(User).filter(User.identifiant == ident).one()
        data = mfa._load(u)
    code = pyotp.TOTP(data["secret"]).at(time.time() + 30)
    r = _login(ident, code)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ── Connexion en deux étapes ─────────────────────────────────────────────────

def test_login_sans_code_exige_le_mfa(compte):
    _activer(compte)
    r = _login(compte)
    assert r.status_code == 401
    assert r.json()["detail"] == "MFA_REQUIRED"
    assert r.headers.get("x-mfa-required") == "true"


def test_login_mauvais_mot_de_passe_ne_revele_pas_le_mfa(compte):
    _activer(compte)
    r = _login(compte, mdp="mauvais-mot-de-passe")
    assert r.status_code == 401
    assert r.json()["detail"] != "MFA_REQUIRED"


def test_login_code_valide_donne_un_jeton(compte):
    secret, _ = _activer(compte)
    r = _login(compte, _code_suivant(secret))
    assert r.status_code == 200
    assert r.json()["access_token"]


def test_login_mauvais_code_refuse_et_audite(compte):
    secret, _ = _activer(compte)
    r = _login(compte, _code_invalide(secret))
    assert r.status_code == 401
    with SessionLocal() as db:
        assert db.query(JournalAudit).filter(
            JournalAudit.action == "MFA_FAILURE", JournalAudit.cible == f"Compte: {compte}"
        ).count() == 1


def test_anti_rejeu_un_code_n_est_utilisable_qu_une_fois(compte):
    secret, _ = _activer(compte)
    code = _code_suivant(secret)
    assert _login(compte, code).status_code == 200
    assert _login(compte, code).status_code == 401


def test_code_trop_ancien_refuse():
    secret = pyotp.random_base32()
    maintenant = 1_700_000_000
    ancien = pyotp.TOTP(secret).at(maintenant - 90)
    assert mfa._matching_step(secret, ancien, maintenant) is None
    assert mfa._matching_step(secret, pyotp.TOTP(secret).at(maintenant - 30), maintenant) is not None


def test_code_de_secours_usage_unique(compte):
    _, codes = _activer(compte)
    assert _login(compte, codes[0]).status_code == 200
    assert _login(compte, codes[0]).status_code == 401
    assert _login(compte, codes[1].upper().replace("-", " ")).status_code == 200  # tolère la casse/séparateurs


def test_cinq_mauvais_codes_verrouillent_le_compte(compte):
    secret, _ = _activer(compte)
    mauvais = _code_invalide(secret)
    statuts = [_login(compte, mauvais).status_code for _ in range(5)]
    assert statuts[:4] == [401] * 4 and statuts[4] == 403
    # même avec un bon code, le compte reste verrouillé
    assert _login(compte, _code_suivant(secret)).status_code == 403


# ── Désactivation et réinitialisation ────────────────────────────────────────

def test_disable_exige_mot_de_passe_et_code(compte):
    secret, codes = _activer(compte)
    h = _headers_apres_mfa(compte)
    r = client.post("/api/v1/auth/mfa/disable", headers=h,
                    json={"mot_de_passe": "faux-mot-de-passe", "code": codes[0]})
    assert r.status_code == 401
    r = client.post("/api/v1/auth/mfa/disable", headers=h,
                    json={"mot_de_passe": MDP, "code": _code_invalide(secret)})
    assert r.status_code == 401
    r = client.post("/api/v1/auth/mfa/disable", headers=h,
                    json={"mot_de_passe": MDP, "code": codes[0]})  # un code de secours est accepté
    assert r.status_code == 200 and r.json()["mfa_active"] is False
    assert _login(compte).status_code == 200


def test_admin_reinitialise_le_mfa_d_un_compte(compte, admin_headers):
    _activer(compte)
    with SessionLocal() as db:
        uid = db.query(User).filter(User.identifiant == compte).one().id
    r = client.post(f"/api/v1/admin/users/{uid}/mfa/reset", headers=admin_headers)
    assert r.status_code == 200 and r.json()["mfa_active"] is False
    assert _login(compte).status_code == 200
    with SessionLocal() as db:
        e = db.query(JournalAudit).filter(JournalAudit.action == "MFA_RESET").order_by(JournalAudit.id.desc()).first()
        assert e.nom_utilisateur == "admin"


def test_admin_reset_utilisateur_inconnu(admin_headers):
    assert client.post("/api/v1/admin/users/999999/mfa/reset", headers=admin_headers).status_code == 404


def test_reset_refuse_au_technicien(tech_headers):
    assert client.post("/api/v1/admin/users/1/mfa/reset", headers=tech_headers).status_code == 403


@pytest.mark.parametrize("url", ["/api/v1/auth/mfa/setup", "/api/v1/auth/mfa/enable", "/api/v1/auth/mfa/disable"])
def test_routes_mfa_exigent_un_jeton(url):
    assert client.post(url, json={"code": "123456", "mot_de_passe": "x"}).status_code == 401


def test_comptes_demo_sans_mfa_se_connectent_toujours():
    assert _login("admin", mdp="AdminPassword2026!").status_code == 200

