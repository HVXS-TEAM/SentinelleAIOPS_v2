"""Tests de non-régression : secrets, CORS, comptes démo et masquage des secrets de notification.

Garantit que :
  - aucune clé publique du dépôt n'est utilisée comme clé active (JWT / Fernet) ;
  - les anciennes données chiffrées avec l'ancienne clé restent lisibles (migration) ;
  - CORS n'autorise que les origines déclarées ;
  - init_db ne réinitialise plus les mots de passe des comptes existants ;
  - GET /admin/notifications/config ne renvoie jamais un secret en clair.
"""
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.app.core import config as cfg
from backend.app.core.config import (
    LEGACY_FERNET_KEY,
    LEGACY_SECRET_KEY,
    Settings,
    settings,
)
from backend.app.core.security import decrypt_secret, encrypt_secret, get_password_hash, verify_password
from backend.app.db.init_db import init_db
from backend.app.db.models import User
from backend.app.db.session import SessionLocal
from backend.app.main import app

client = TestClient(app)


# ── Clés actives ─────────────────────────────────────────────────────────────

def test_cles_actives_ne_sont_pas_les_cles_publiques():
    assert settings.SECRET_KEY != LEGACY_SECRET_KEY
    assert settings.FERNET_KEY != LEGACY_FERNET_KEY
    assert len(settings.SECRET_KEY) >= 32
    Fernet(settings.FERNET_KEY.encode())  # clé Fernet valide


def test_demarrage_refuse_secret_key_publique():
    with pytest.raises(ValidationError):
        Settings(SECRET_KEY=LEGACY_SECRET_KEY)


def test_demarrage_refuse_secret_key_trop_courte():
    with pytest.raises(ValidationError):
        Settings(SECRET_KEY="trop-court")


def test_demarrage_refuse_fernet_key_publique():
    with pytest.raises(ValidationError):
        Settings(FERNET_KEY=LEGACY_FERNET_KEY)


def test_demarrage_refuse_fernet_key_invalide():
    with pytest.raises(ValidationError):
        Settings(FERNET_KEY="pas-une-cle-fernet")


def test_cles_fournies_par_environnement_sont_respectees():
    custom_secret = "x" * 48
    custom_fernet = Fernet.generate_key().decode()
    s = Settings(SECRET_KEY=custom_secret, FERNET_KEY=custom_fernet)
    assert s.SECRET_KEY == custom_secret
    assert s.FERNET_KEY == custom_fernet


def test_secrets_persistes_dans_un_fichier_local(tmp_path, monkeypatch):
    """Premier démarrage : génération puis réutilisation de la même valeur."""
    monkeypatch.setattr(cfg, "SECRETS_FILE", tmp_path / ".sentinelle_secrets.json")
    premiere = cfg._persisted_secret("SECRET_KEY", lambda: "valeur-A" + "a" * 40)
    seconde = cfg._persisted_secret("SECRET_KEY", lambda: "valeur-B" + "b" * 40)
    assert premiere == seconde  # le générateur n'est pas rappelé : valeur conservée
    assert (tmp_path / ".sentinelle_secrets.json").exists()


def test_fernet_non_persistable_leve_une_erreur(tmp_path, monkeypatch):
    """Si la clé Fernet ne peut pas être sauvegardée, on refuse de démarrer (sinon données perdues)."""
    monkeypatch.setattr(cfg, "SECRETS_FILE", tmp_path / "dossier_inexistant" / "s.json")
    with pytest.raises(RuntimeError):
        cfg._persisted_secret("FERNET_KEY", lambda: Fernet.generate_key().decode(), must_persist=True)


# ── Migration : anciennes données chiffrées ──────────────────────────────────

def test_ancien_secret_chiffre_reste_dechiffrable():
    """Un secret chiffré avec l'ancienne clé publique (ex: notification_settings.json) reste lisible."""
    from backend.app.core.security import _legacy_fernet

    ancien = _legacy_fernet().encrypt(b"ancien-token-123").decode()
    assert decrypt_secret(ancien) == "ancien-token-123"


def test_nouveau_secret_chiffre_avec_la_cle_active_uniquement():
    from backend.app.core.security import _legacy_fernet
    from cryptography.fernet import InvalidToken

    chiffre = encrypt_secret("nouveau-secret")
    assert decrypt_secret(chiffre) == "nouveau-secret"
    with pytest.raises(InvalidToken):
        _legacy_fernet().decrypt(chiffre.encode())  # l'ancienne clé publique ne peut plus le lire


# ── CORS ─────────────────────────────────────────────────────────────────────

def test_cors_refuse_une_origine_inconnue():
    resp = client.get("/", headers={"Origin": "https://evil.example"})
    assert resp.headers.get("access-control-allow-origin") is None


def test_cors_refuse_le_joker():
    resp = client.get("/", headers={"Origin": "https://evil.example"})
    assert resp.headers.get("access-control-allow-origin") != "*"


def test_cors_accepte_le_front_de_developpement():
    resp = client.get("/", headers={"Origin": "http://localhost:5173"})
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"


# ── Comptes démo ─────────────────────────────────────────────────────────────

def test_init_db_ne_reinitialise_pas_un_mot_de_passe_modifie():
    """Un mot de passe changé (et le blocage éventuel) survivent à un redémarrage."""
    nouveau_hash = get_password_hash("MotDePasseChange2026!")
    with SessionLocal() as db:
        user = db.query(User).filter(User.identifiant == "visiteur").first()
        assert user is not None
        ancien_hash = user.hash_mot_de_passe
        user.hash_mot_de_passe = nouveau_hash
        user.est_actif = False
        db.commit()
    try:
        with SessionLocal() as db:
            init_db(db)
        with SessionLocal() as db:
            user = db.query(User).filter(User.identifiant == "visiteur").first()
            assert user.hash_mot_de_passe == nouveau_hash
            assert verify_password("MotDePasseChange2026!", user.hash_mot_de_passe)
            assert user.est_actif is False  # un compte désactivé par l'admin le reste
    finally:
        with SessionLocal() as db:
            user = db.query(User).filter(User.identifiant == "visiteur").first()
            user.hash_mot_de_passe = ancien_hash
            user.est_actif = True
            db.commit()


def test_init_db_n_injecte_aucune_donnee():
    """Production uniquement : init_db ne crée ni compte ni équipement."""
    from backend.app.db.models import Equipement
    with SessionLocal() as db:
        avant = (db.query(User).count(), db.query(Equipement).count())
        init_db(db)
        assert (db.query(User).count(), db.query(Equipement).count()) == avant


# ── Secrets de notification masqués ──────────────────────────────────────────

def _payload(**over):
    base = {
        "demo_mode": False,
        "telegram_enabled": True,
        "telegram_token": "123456:ABCDEF",
        "telegram_chat_id": "@sentinelle_soc",
        "discord_enabled": True,
        "discord_webhook": "https://discord.com/api/webhooks/1/abc",
        "email_enabled": True,
        "smtp_server": "smtp.sentinelle.local",
        "smtp_port": 587,
        "email_recipient": "soc@sentinelle.local",
        "email_use_tls": True,
    }
    base.update(over)
    return base


def test_config_notifications_ne_renvoie_jamais_les_secrets(admin_headers):
    r = client.put("/api/v1/admin/notifications/config", json=_payload(), headers=admin_headers)
    assert r.status_code == 200
    for data in (r.json(), client.get("/api/v1/admin/notifications/config", headers=admin_headers).json()):
        assert data["telegram_token"] == ""
        assert data["discord_webhook"] == ""
        assert data["telegram_token_set"] is True
        assert data["discord_webhook_set"] is True
        assert "123456:ABCDEF" not in str(data)
        assert "discord.com/api/webhooks" not in str(data)


def test_secret_vide_conserve_la_valeur_enregistree(admin_headers):
    from backend.app.modules.admin.service import AdminService

    client.put("/api/v1/admin/notifications/config", json=_payload(), headers=admin_headers)
    # Nouvelle sauvegarde SANS ressaisir les secrets (cas normal de l'écran Admin)
    r = client.put(
        "/api/v1/admin/notifications/config",
        json=_payload(telegram_token="", discord_webhook="", email_recipient="autre@sentinelle.local"),
        headers=admin_headers,
    )
    assert r.status_code == 200
    interne = AdminService.get_notification_settings(include_secrets=True)
    assert interne["telegram_token"] == "123456:ABCDEF"
    assert interne["discord_webhook"] == "https://discord.com/api/webhooks/1/abc"
    assert interne["email_recipient"] == "autre@sentinelle.local"


def test_secret_remplace_et_supprime_explicitement(admin_headers):
    from backend.app.modules.admin.service import AdminService

    client.put("/api/v1/admin/notifications/config", json=_payload(), headers=admin_headers)
    client.put(
        "/api/v1/admin/notifications/config",
        json=_payload(telegram_token="999:NOUVEAU", discord_webhook="", clear_discord_webhook=True),
        headers=admin_headers,
    )
    interne = AdminService.get_notification_settings(include_secrets=True)
    assert interne["telegram_token"] == "999:NOUVEAU"
    assert interne["discord_webhook"] == ""
    r = client.get("/api/v1/admin/notifications/config", headers=admin_headers).json()
    assert r["telegram_token_set"] is True
    assert r["discord_webhook_set"] is False

