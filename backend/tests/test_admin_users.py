"""Gestion des comptes par l'administrateur : changement de rôle, garde-fous, secrets de notification."""
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.app.core.security import get_password_hash
from backend.app.db.models import JournalAudit, User
from backend.app.db.session import SessionLocal
from backend.app.main import app
from backend.app.modules.admin.notifications import NotificationService
from backend.app.modules.admin.service import AdminService
from backend.app.schemas.admin import NotificationTestResponse

client = TestClient(app)


@pytest.fixture()
def compte():
    ident = f"role_{uuid.uuid4().hex[:8]}"
    with SessionLocal() as db:
        u = User(identifiant=ident, email=f"{ident}@sentinelle.local", nom_complet="Compte Role",
                 hash_mot_de_passe=get_password_hash("MotDePasse2026!"), role="Visiteur", est_actif=True, mfa_active=False)
        db.add(u)
        db.commit()
        uid = u.id
    yield uid, ident
    with SessionLocal() as db:
        db.query(User).filter(User.id == uid).delete()
        db.commit()


def _id_admin() -> int:
    with SessionLocal() as db:
        return db.query(User).filter(User.identifiant == "admin").one().id


def test_admin_change_le_role_et_l_audit_nomme_l_auteur(compte, admin_headers):
    uid, ident = compte
    r = client.put(f"/api/v1/admin/users/{uid}/role", headers=admin_headers, json={"role": "Technicien"})
    assert r.status_code == 200 and r.json()["role"] == "Technicien"
    with SessionLocal() as db:
        assert db.query(User).filter(User.id == uid).one().role == "Technicien"
        e = db.query(JournalAudit).filter(JournalAudit.action == "USER_ROLE_CHANGE",
                                           JournalAudit.cible == f"User:{ident}").order_by(JournalAudit.id.desc()).first()
        assert e is not None and e.nom_utilisateur == "admin" and "Visiteur -> Technicien" in e.details


def test_role_invalide_refuse(compte, admin_headers):
    uid, _ = compte
    assert client.put(f"/api/v1/admin/users/{uid}/role", headers=admin_headers, json={"role": "Root"}).status_code == 422


def test_role_utilisateur_inconnu(admin_headers):
    assert client.put("/api/v1/admin/users/999999/role", headers=admin_headers, json={"role": "Visiteur"}).status_code == 404


def test_admin_ne_peut_pas_modifier_son_propre_role(admin_headers):
    r = client.put(f"/api/v1/admin/users/{_id_admin()}/role", headers=admin_headers, json={"role": "Visiteur"})
    assert r.status_code == 409


def test_admin_ne_peut_pas_se_desactiver(admin_headers):
    assert client.put(f"/api/v1/admin/users/{_id_admin()}/status", headers=admin_headers).status_code == 409


def test_dernier_administrateur_protege_au_niveau_service():
    """Défense en profondeur : même un appelant tiers ne peut pas retirer le dernier administrateur actif."""
    with SessionLocal() as db:
        actifs = db.query(User).filter(User.role == "Administrateur", User.est_actif.is_(True)).count()
        if actifs != 1:
            pytest.skip("plus d'un administrateur actif dans la base de test")
        with pytest.raises(PermissionError):
            AdminService.update_user_role(db, _id_admin(), "Visiteur", current_admin_user="autre_admin")
        with pytest.raises(PermissionError):
            AdminService.toggle_user_status(db, _id_admin(), current_admin_user="autre_admin")


def test_technicien_ne_peut_pas_changer_un_role(compte, tech_headers):
    uid, _ = compte
    assert client.put(f"/api/v1/admin/users/{uid}/role", headers=tech_headers, json={"role": "Administrateur"}).status_code == 403


# ── Test de notification avec secret déjà enregistré ─────────────────────────

def test_test_telegram_reprend_le_jeton_enregistre(monkeypatch, admin_headers):
    vu = {}

    def faux_test(config, message):
        vu["token"] = config.bot_token
        return NotificationTestResponse(success=True, channel="telegram", message="ok")

    monkeypatch.setattr(AdminService, "get_notification_settings",
                        staticmethod(lambda include_secrets=False: {"telegram_token": "jeton-stocke", "discord_webhook": ""}))
    monkeypatch.setattr(NotificationService, "test_telegram", staticmethod(faux_test))
    r = client.post("/api/v1/admin/notifications/test", headers=admin_headers,
                    json={"channel": "telegram", "telegram_config": {"bot_token": "", "chat_id": "@canal"}})
    assert r.status_code == 200 and vu["token"] == "jeton-stocke"


def test_test_telegram_sans_aucun_jeton_refuse(monkeypatch, admin_headers):
    monkeypatch.setattr(AdminService, "get_notification_settings",
                        staticmethod(lambda include_secrets=False: {"telegram_token": "", "discord_webhook": ""}))
    r = client.post("/api/v1/admin/notifications/test", headers=admin_headers,
                    json={"channel": "telegram", "telegram_config": {"bot_token": "", "chat_id": "@canal"}})
    assert r.status_code == 400


def test_test_discord_sans_webhook_refuse(monkeypatch, admin_headers):
    monkeypatch.setattr(AdminService, "get_notification_settings",
                        staticmethod(lambda include_secrets=False: {"telegram_token": "", "discord_webhook": ""}))
    r = client.post("/api/v1/admin/notifications/test", headers=admin_headers,
                    json={"channel": "discord", "discord_config": {"webhook_url": ""}})
    assert r.status_code == 400
