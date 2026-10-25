"""Tests d'intégration et unitaires du Socle (Base de données, Sécurité, Authentification, RBAC)."""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.security import get_password_hash, verify_password, encrypt_secret, decrypt_secret
from backend.app.db.session import SessionLocal
from backend.app.db.models import User, JournalAudit

client = TestClient(app)


def test_password_hashing():
    """Vérifie que le hachage bcrypt fonctionne et est non réversible."""
    plain = "MonSuperMotDePasse2026!"
    hashed = get_password_hash(plain)
    assert hashed != plain
    assert verify_password(plain, hashed) is True
    assert verify_password("MauvaisPasse", hashed) is False


def test_fernet_encryption():
    """Vérifie le chiffrement et déchiffrement réversible des identifiants équipements."""
    secret = "cisco:enable_secret_2026"
    encrypted = encrypt_secret(secret)
    assert encrypted != secret
    decrypted = decrypt_secret(encrypted)
    assert decrypted == secret


def test_login_success_admin():
    """Vérifie la connexion d'un compte administrateur et la génération du token JWT."""
    response = client.post(
        "/api/v1/auth/login",
        json={"identifiant": "admin", "mot_de_passe": "AdminPassword2026!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["role"] == "Administrateur"
    assert data["identifiant"] == "admin"


def test_login_failure():
    """Vérifie le rejet d'une tentative de connexion erronée."""
    response = client.post(
        "/api/v1/auth/login",
        json={"identifiant": "admin", "mot_de_passe": "FauxMotDePasse"},
    )
    assert response.status_code == 401
    assert "detail" in response.json()


def test_read_profile_with_jwt():
    """Vérifie la lecture du profil authentifié via le Bearer Token."""
    # 1. Login
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"identifiant": "tech", "mot_de_passe": "TechPassword2026!"},
    )
    token = login_resp.json()["access_token"]

    # 2. Me
    me_resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    user_data = me_resp.json()
    assert user_data["identifiant"] == "tech"
    assert user_data["role"] == "Technicien"


def test_audit_trail_recorded():
    """Vérifie qu'un événement d'audit est bien inséré en base lors d'une connexion."""
    db = SessionLocal()
    recent_logs = db.query(JournalAudit).filter(JournalAudit.action == "LOGIN_SUCCESS").all()
    db.close()
    assert len(recent_logs) > 0


def test_register_user_success():
    """Vérifie la création réelle d'un nouvel utilisateur et la possibilité de s'authentifier immédiatement."""
    test_id = "edwin_test_user"
    test_email = "edwin.test@sentinelle.local"
    test_pass = "SecurePass2026!"

    # Nettoyage préventif
    db = SessionLocal()
    old = db.query(User).filter((User.identifiant == test_id) | (User.email == test_email)).first()
    if old:
        db.delete(old)
        db.commit()
    db.close()

    # 1. Inscription
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "identifiant": test_id,
            "email": test_email,
            "nom_complet": "Edwin Jamel",
            "mot_de_passe": test_pass,
            "role": "Administrateur",
        },
    )
    assert reg_resp.status_code == 200
    data = reg_resp.json()
    assert data["identifiant"] == test_id
    assert data["role"] == "Administrateur"
    assert "access_token" in data

    # 2. Vérification connexion directe avec les nouveaux identifiants
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"identifiant": test_id, "mot_de_passe": test_pass},
    )
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    assert login_data["identifiant"] == test_id
    assert login_data["role"] == "Administrateur"


def test_register_duplicate_user():
    """Vérifie le rejet d'un doublon lors de la création de compte."""
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "identifiant": "admin",
            "email": "admin@sentinelle.local",
            "nom_complet": "Doublon",
            "mot_de_passe": "AutrePass2026!",
            "role": "Technicien",
        },
    )
    assert resp.status_code == 400
    assert "existe déjà" in resp.json()["detail"]


def test_account_lockout_after_five_failed_attempts():
    """Valide la politique de sécurité CDC : verrouillage temporaire après 5 échecs consécutifs."""
    import time
    from datetime import datetime, timezone, timedelta

    test_user = f"user_lock_{int(time.time())}"
    test_pass = "SecurePass2026!"

    # 1. Création d'un compte de test
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={
            "identifiant": test_user,
            "email": f"{test_user}@sentinelle.local",
            "nom_complet": "Test Lockout",
            "mot_de_passe": test_pass,
            "role": "Technicien",
        },
    )
    assert reg_resp.status_code == 200

    # 2. 4 premières tentatives erronées -> Doivent échouer avec 401
    for i in range(1, 5):
        resp = client.post(
            "/api/v1/auth/login",
            json={"identifiant": test_user, "mot_de_passe": "MauvaisMotDePasse"},
        )
        assert resp.status_code == 401
        assert "incorrect" in resp.json()["detail"]

    # 3. 5ème tentative erronée -> Doit déclencher le verrouillage temporaire (403)
    resp_5 = client.post(
        "/api/v1/auth/login",
        json={"identifiant": test_user, "mot_de_passe": "MauvaisMotDePasse"},
    )
    assert resp_5.status_code == 403
    assert "verrouillé" in resp_5.json()["detail"].lower()

    # 4. 6ème tentative, même avec le BON mot de passe -> Rejet 403 tant que verrouillé
    resp_locked = client.post(
        "/api/v1/auth/login",
        json={"identifiant": test_user, "mot_de_passe": test_pass},
    )
    assert resp_locked.status_code == 403
    assert "verrouillé" in resp_locked.json()["detail"].lower()

    # 5. Déverrouillage automatique après écoulement du délai (simulé en base)
    db = SessionLocal()
    u = db.query(User).filter(User.identifiant == test_user).first()
    assert u.tentatives_echouees == 5
    assert u.bloque_jusqu_a is not None
    # Simulation du délai passé (il y a 1 minute)
    u.bloque_jusqu_a = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    db.close()

    # 6. Connexion avec le bon mot de passe -> Succès 200 et réinitialisation des compteurs
    resp_unlock = client.post(
        "/api/v1/auth/login",
        json={"identifiant": test_user, "mot_de_passe": test_pass},
    )
    assert resp_unlock.status_code == 200
    assert "access_token" in resp_unlock.json()

    # Vérification que le compteur est remis à 0
    db = SessionLocal()
    u = db.query(User).filter(User.identifiant == test_user).first()
    assert u.tentatives_echouees == 0
    assert u.bloque_jusqu_a is None
    db.close()


