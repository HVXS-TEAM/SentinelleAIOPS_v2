"""Tests de non-régression sécurité : authentification obligatoire et RBAC strict.

Garantit que :
  - aucune route métier (admin, netdevops, dashboard, assistant) n'est joignable sans jeton ;
  - les rôles respectent la matrice du README (Visiteur < Technicien < Administrateur) ;
  - l'auto-inscription ne permet jamais de choisir un rôle privilégié ;
  - /api/v1/health reste publique et vérifie réellement la base de données.

Seuls des refus (401/403) sont testés sur les routes sensibles : leur code métier
n'est donc jamais exécuté (aucun effet de bord sur la base ni sur le réseau).
"""
import uuid

import pytest
from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.db.models import JournalAudit, User
from backend.app.db.session import SessionLocal
from backend.app.main import app

client = TestClient(app)

# Routes réservées à l'Administrateur
ROUTES_ADMIN_ONLY = [
    ("GET", "/api/v1/admin/users"),
    ("POST", "/api/v1/admin/users"),
    ("PUT", "/api/v1/admin/users/1/status"),
    ("POST", "/api/v1/admin/users/1/mfa/reset"),
    ("PUT", "/api/v1/admin/users/1/role"),
    ("GET", "/api/v1/admin/audit-logs"),
    ("POST", "/api/v1/admin/pra/backup"),
    ("GET", "/api/v1/admin/pra/backups"),
    ("POST", "/api/v1/admin/pra/verify/inexistant.db"),
    ("POST", "/api/v1/admin/pra/restore/inexistant.db"),
    ("GET", "/api/v1/admin/pra/metrics"),
    ("GET", "/api/v1/admin/notifications/config"),
    ("PUT", "/api/v1/admin/notifications/config"),
]

# Routes réservées aux opérateurs (Administrateur + Technicien)
ROUTES_OPERATEURS = [
    ("POST", "/api/v1/netdevops/audit/SW-CORE-01"),
    ("POST", "/api/v1/netdevops/remediate/SW-CORE-01"),
    ("POST", "/api/v1/netdevops/restore/SW-CORE-01"),
    ("POST", "/api/v1/dashboard/refresh"),
    ("POST", "/api/v1/parc/recalculate-scores"),
    ("POST", "/api/v1/admin/notifications/test"),
    ("POST", "/api/v1/admin/notifications/dispatch"),
]

# Routes de lecture ouvertes à tout utilisateur authentifié
ROUTES_LECTURE = [
    ("GET", "/api/v1/netdevops/devices"),
    ("GET", "/api/v1/netdevops/backups/SW-CORE-01"),
    ("GET", "/api/v1/dashboard/summary"),
    ("GET", "/api/v1/assistant/suggested-prompts"),
    ("POST", "/api/v1/assistant/chat"),
    ("GET", "/api/v1/admin/reports/generate-pdf"),
]

TOUTES_LES_ROUTES = ROUTES_ADMIN_ONLY + ROUTES_OPERATEURS + ROUTES_LECTURE


@pytest.mark.parametrize("method,url", TOUTES_LES_ROUTES)
def test_route_sans_jeton_refusee(method, url):
    """Aucune route métier ne doit répondre sans authentification."""
    resp = client.request(method, url)
    assert resp.status_code == 401, f"{method} {url} -> {resp.status_code}"


@pytest.mark.parametrize("method,url", TOUTES_LES_ROUTES)
def test_route_jeton_invalide_refusee(method, url):
    """Un jeton falsifié ou illisible doit être rejeté."""
    resp = client.request(method, url, headers={"Authorization": "Bearer jeton.invalide.xyz"})
    assert resp.status_code == 401, f"{method} {url} -> {resp.status_code}"


@pytest.mark.parametrize("method,url", ROUTES_ADMIN_ONLY + ROUTES_OPERATEURS)
def test_visiteur_ne_peut_pas_agir(method, url, visiteur_headers):
    """Le Visiteur est en lecture seule : 403 sur toute action privilégiée."""
    resp = client.request(method, url, headers=visiteur_headers)
    assert resp.status_code == 403, f"{method} {url} -> {resp.status_code}"


@pytest.mark.parametrize("method,url", ROUTES_ADMIN_ONLY)
def test_technicien_ne_peut_pas_administrer(method, url, tech_headers):
    """Le Technicien n'a accès à aucune route d'administration exclusive."""
    resp = client.request(method, url, headers=tech_headers)
    assert resp.status_code == 403, f"{method} {url} -> {resp.status_code}"


@pytest.mark.parametrize(
    "url",
    [
        "/api/v1/netdevops/devices",
        "/api/v1/dashboard/summary",
        "/api/v1/assistant/suggested-prompts",
    ],
)
def test_visiteur_peut_consulter(url, visiteur_headers):
    """Le Visiteur conserve l'accès en lecture aux écrans de consultation."""
    assert client.get(url, headers=visiteur_headers).status_code == 200


def test_admin_peut_lister_les_utilisateurs(admin_headers):
    resp = client.get("/api/v1/admin/users", headers=admin_headers)
    assert resp.status_code == 200
    assert any(u["identifiant"] == "admin" for u in resp.json())


def test_inscription_ignore_le_role_demande():
    """Anti-élévation de privilèges : un rôle privilégié demandé est forcé à Visiteur."""
    ident = f"intrus_{uuid.uuid4().hex[:8]}"
    try:
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "identifiant": ident,
                "email": f"{ident}@sentinelle.local",
                "nom_complet": "Tentative Escalade",
                "mot_de_passe": "MotDePasse2026!",
                "role": "Administrateur",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "Visiteur"
        # Le jeton obtenu ne donne aucun accès administrateur
        headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}
        assert client.get("/api/v1/admin/users", headers=headers).status_code == 403
    finally:
        with SessionLocal() as db:
            db.query(User).filter(User.identifiant == ident).delete()
            db.commit()


def test_inscription_mot_de_passe_trop_court():
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "identifiant": f"court_{uuid.uuid4().hex[:6]}",
            "email": f"court_{uuid.uuid4().hex[:6]}@sentinelle.local",
            "nom_complet": "Mot de passe court",
            "mot_de_passe": "1234567",
        },
    )
    assert resp.status_code == 400


def test_inscription_desactivable(monkeypatch):
    """ALLOW_SELF_REGISTRATION=False ferme complètement l'inscription publique."""
    monkeypatch.setattr(settings, "ALLOW_SELF_REGISTRATION", False)
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "identifiant": f"ferme_{uuid.uuid4().hex[:6]}",
            "email": f"ferme_{uuid.uuid4().hex[:6]}@sentinelle.local",
            "nom_complet": "Inscription fermée",
            "mot_de_passe": "MotDePasse2026!",
        },
    )
    assert resp.status_code == 403


def test_creation_compte_admin_attribuee_a_l_auteur(admin_headers):
    """Seul un administrateur crée un compte privilégié, et l'audit nomme l'auteur réel."""
    ident = f"adm_{uuid.uuid4().hex[:8]}"
    created_id = None
    try:
        resp = client.post(
            "/api/v1/admin/users",
            headers=admin_headers,
            json={
                "identifiant": ident,
                "email": f"{ident}@sentinelle.local",
                "nom_complet": "Compte Créé Par Admin",
                "mot_de_passe": "MotDePasse2026!",
                "role": "Technicien",
            },
        )
        assert resp.status_code == 200
        created_id = resp.json()["id"]
        assert resp.json()["role"] == "Technicien"

        with SessionLocal() as db:
            entry = (
                db.query(JournalAudit)
                .filter(JournalAudit.action == "USER_CREATE", JournalAudit.cible == f"User:{ident}")
                .order_by(JournalAudit.id.desc())
                .first()
            )
            assert entry is not None
            assert entry.nom_utilisateur == "admin"
    finally:
        if created_id:
            with SessionLocal() as db:
                db.query(User).filter(User.id == created_id).delete()
                db.commit()


def test_health_publique_et_verifie_la_base():
    """/api/v1/health reste accessible sans jeton et teste réellement la base."""
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["database"] == "ok"

