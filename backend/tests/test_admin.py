"""Tests unitaires et d'intégration du module Administration, RBAC et Continuité d'Activité (PRA)."""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.db.session import SessionLocal
from backend.app.modules.admin.service import AdminService

client = TestClient(app)


def test_users_list_and_rbac():
    """Vérifie la liste des utilisateurs et le rôle d'administration par défaut."""
    db = SessionLocal()
    try:
        users = AdminService.list_users(db)
        assert len(users) >= 1
        admin_user = next((u for u in users if u["identifiant"] == "admin"), None)
        assert admin_user is not None
        assert admin_user["role"] == "Administrateur"
        assert admin_user["est_actif"] is True
    finally:
        db.close()


def test_user_creation_and_status_toggle():
    """Vérifie la création d'un nouvel utilisateur et la modification de son statut actif."""
    import uuid
    from backend.app.db.models import User
    db = SessionLocal()
    created_id = None
    try:
        unique_id = f"tech_{uuid.uuid4().hex[:8]}"
        created = AdminService.create_user(
            db,
            identifiant=unique_id,
            email=f"{unique_id}@bts-sio.lab",
            nom_complet="Technicien Test Unitaire",
            mot_de_passe="Password1234!",
            role="Technicien",
        )
        created_id = created["id"]
        assert created["identifiant"] == unique_id
        assert created["role"] == "Technicien"

        # Toggle statut
        toggled = AdminService.toggle_user_status(db, user_id=created["id"])
        assert toggled["est_actif"] is False

        toggled_back = AdminService.toggle_user_status(db, user_id=created["id"])
        assert toggled_back["est_actif"] is True
    finally:
        if created_id:
            db.query(User).filter(User.id == created_id).delete()
            db.commit()
        db.close()


def test_audit_logs_retrieval():
    """Vérifie l'accès au journal d'audit inaltérable et le filtrage."""
    db = SessionLocal()
    try:
        logs = AdminService.get_audit_logs(db, limit=50)
        assert len(logs) >= 1
        assert "action" in logs[0]
        assert "cible" in logs[0]
        assert "horodatage" in logs[0]
    finally:
        db.close()


def test_pra_backup_and_integrity_verification():
    """Vérifie la génération à chaud d'une sauvegarde de base avec son empreinte SHA-256."""
    db = SessionLocal()
    try:
        backup_info = AdminService.trigger_pra_backup(db, triggered_by="admin_test")
        assert "filename" in backup_info
        assert len(backup_info["sha256"]) == 64
        assert backup_info["size_kb"] > 0

        # Vérification d'intégrité
        verif = AdminService.verify_backup_integrity(backup_info["filename"])
        assert verif["is_valid"] is True
        assert verif["expected_sha256"] == verif["actual_sha256"]

        # Métriques PRA
        metrics = AdminService.get_pra_metrics()
        assert metrics["rto_cible_minutes"] == 5
        assert metrics["rpo_cible_heures"] == 24
        assert metrics["total_sauvegardes"] >= 1
    finally:
        db.close()


def test_api_admin_endpoints():
    """Vérifie les points de terminaison REST /api/v1/admin."""
    # 1. Users list
    resp_users = client.get("/api/v1/admin/users")
    assert resp_users.status_code == 200
    assert len(resp_users.json()) >= 1

    # 2. Audit logs
    resp_audit = client.get("/api/v1/admin/audit-logs?limit=10")
    assert resp_audit.status_code == 200
    assert isinstance(resp_audit.json(), list)

    # 3. PRA Backups list
    resp_backups = client.get("/api/v1/admin/pra/backups")
    assert resp_backups.status_code == 200
    assert isinstance(resp_backups.json(), list)

    # 4. PRA Metrics
    resp_metrics = client.get("/api/v1/admin/pra/metrics")
    assert resp_metrics.status_code == 200
    assert "rto_cible_minutes" in resp_metrics.json()
    assert "rpo_cible_heures" in resp_metrics.json()


def test_api_generate_pdf_report():
    """Vérifie la génération et le téléchargement d'un flux binaire PDF d'audit."""
    login_resp = client.post("/api/v1/auth/login", json={"identifiant": "admin", "mot_de_passe": "AdminPassword2026!"})
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/v1/admin/reports/generate-pdf?title=Bilan_Test_BTS", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "attachment; filename=" in resp.headers.get("content-disposition", "")
    assert len(resp.content) > 1000
    assert resp.content.startswith(b"%PDF")

