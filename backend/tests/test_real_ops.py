"""Tests d'intégration des nouvelles capacités temps réel de Sentinelle AIOps v2.

Valide :
- Le cycle de vie complet des alertes (Acquittement & Résolution)
- Le sondage actif d'équipement et la mise à jour d'identifiants SSH chiffrés
- Le scan réel de cybersécurité, le blocage actif d'adresse IP et l'isolement d'équipement
- La remédiation CIS automatique et la restauration de configuration NetDevOps
- La restauration PRA de sauvegarde SQLite et la persistance chiffrée des notifications
- Le rafraîchissement global des séries temporelles du Dashboard
"""
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def _get_admin_headers() -> dict[str, str]:
    resp = client.post(
        "/api/v1/auth/login",
        json={"identifiant": "admin", "mot_de_passe": "AdminPassword2026!"},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_real_alert_lifecycle_and_probing():
    """Vérifie la liste des alertes, leur acquittement, leur résolution et le sondage d'équipement."""
    headers = _get_admin_headers()

    # Alerte de test créée dans la base temporaire (l'application n'en fabrique aucune)
    from backend.app.db.session import SessionLocal
    from backend.app.db.models import Alerte
    with SessionLocal() as db:
        db.add(Alerte(module_origine="Supervision", severite="WARNING", titre="Alerte de test",
                      message="Alerte créée par le test", statut="Active"))
        db.commit()

    # 1. Lister les alertes
    resp_alerts = client.get("/api/v1/supervision/alerts?statut=Toutes", headers=headers)
    assert resp_alerts.status_code == 200
    alerts = resp_alerts.json()
    assert isinstance(alerts, list)
    assert len(alerts) >= 1

    first_alert_id = alerts[0]["id"]

    # 2. Acquitter l'alerte
    resp_ack = client.put(f"/api/v1/supervision/alerts/{first_alert_id}/acknowledge", headers=headers)
    assert resp_ack.status_code == 200
    assert resp_ack.json()["statut"] == "Acquittée"

    # 3. Résoudre l'alerte
    resp_res = client.put(f"/api/v1/supervision/alerts/{first_alert_id}/resolve", headers=headers)
    assert resp_res.status_code == 200
    assert resp_res.json()["statut"] == "Résolue"


def test_real_parc_update_and_probe():
    """Vérifie l'enrichissement des équipements, la mise à jour SSH et le sondage unitaire."""
    headers = _get_admin_headers()

    resp_list = client.get("/api/v1/parc/equipements", headers=headers)
    assert resp_list.status_code == 200
    items = resp_list.json()
    assert len(items) >= 1

    target = next(e for e in items if e["nom"] == "SW-CORE-01")
    assert "cpu_history" in target
    assert "ram_history" in target
    assert "cis_status" in target

    # Mise à jour de l'équipement avec identifiants SSH chiffrés
    resp_upd = client.put(
        f"/api/v1/parc/equipements/{target['id']}",
        json={"groupe": "Cœur de réseau", "mot_de_passe_secret": "admin:secret123"},
        headers=headers,
    )
    assert resp_upd.status_code == 200
    assert resp_upd.json()["has_ssh_credentials"] is True

    # Sondage unitaire
    resp_probe = client.post(f"/api/v1/parc/equipements/{target['id']}/probe", headers=headers)
    assert resp_probe.status_code == 200
    assert "probe" in resp_probe.json()
    assert "latency_ms" in resp_probe.json()["probe"]


def test_real_security_scan_and_firewall_actions(monkeypatch):
    """Vérifie le scan de sécurité de l'hôte, le blocage d'IP et l'isolement d'équipement."""
    headers = _get_admin_headers()

    # 1. Scan sécurité réel
    resp_scan = client.post("/api/v1/securite/scan-real", headers=headers)
    assert resp_scan.status_code == 200
    assert "sources" in resp_scan.json() and "modele" in resp_scan.json()

    # Le pare-feu de l'hôte n'est pas modifié par les tests : on simule uniquement la réponse du système
    from backend.app.modules.securite.service import SecurityService
    monkeypatch.setattr(SecurityService, "_apply_firewall_block", staticmethod(lambda ip, rule: (True, "IPTABLES", "Règle créée.")))

    # 2. Blocage actif d'IP
    resp_block = client.post(
        "/api/v1/securite/block-ip",
        json={"source_ip": "198.51.100.77", "motif": "Test blocage pare-feu"},
        headers=headers,
    )
    assert resp_block.status_code == 200
    assert resp_block.json()["status"] == "BLOCKED"

    # 3. Isolement d'équipement
    eqs = client.get("/api/v1/parc/equipements", headers=headers).json()
    cible = next(e for e in eqs if e["nom"] == "SRV-DB-01")
    resp_iso = client.post(
        "/api/v1/securite/isolate-device",
        json={"equipement_id": cible["id"], "device_name": cible["nom"], "motif": "Quarantaine préventive"},
        headers=headers,
    )
    assert resp_iso.status_code == 200
    assert resp_iso.json()["status"] == "QUARANTINE_MARKED"
    assert resp_iso.json()["network_action_performed"] is False


def test_real_netdevops_remediation_and_restore(faux_cisco):
    """Vérifie l'application réelle des correctifs CIS et la restauration de configuration."""
    headers = _get_admin_headers()

    # 1. Appliquer la remédiation CIS sur SW-CORE-01
    resp_rem = client.post(
        "/api/v1/netdevops/remediate/SW-CORE-01",
        json={"remediation_snippet": "service password-encryption", "rule_id": "CIS-1.1"},
        headers=headers,
    )
    assert resp_rem.status_code == 200
    rem_data = resp_rem.json()
    assert "audit" in rem_data
    assert rem_data["audit"]["score"] >= 0.0
    assert rem_data["ssh_mode"] == "REAL_SSH_APPLIED"
    assert faux_cisco.pushes == ["service password-encryption"]

    # 2. Restaurer la sauvegarde initiale
    resp_rest = client.post(
        "/api/v1/netdevops/restore/SW-CORE-01",
        json={"backup_index": 0},
        headers=headers,
    )
    assert resp_rest.status_code == 200
    assert "audit" in resp_rest.json()


def test_real_admin_pra_restore_and_notification_persistence():
    """Vérifie la restauration PRA SQLite et la sauvegarde chiffrée des paramètres de notification."""
    headers = _get_admin_headers()

    # 1. Créer une sauvegarde PRA puis la restaurer
    resp_bkp = client.post("/api/v1/admin/pra/backup", headers=headers)
    assert resp_bkp.status_code == 200
    filename = resp_bkp.json()["filename"]

    resp_rest = client.post(f"/api/v1/admin/pra/restore/{filename}", headers=headers)
    assert resp_rest.status_code == 200
    assert resp_rest.json()["status"] == "RESTORED"

    # 2. Sauvegarder et relire la configuration des notifications
    payload = {
        "demo_mode": False,
        "telegram_enabled": True,
        "telegram_token": "123456:ABCDEF",
        "telegram_chat_id": "@sentinelle_soc",
        "discord_enabled": False,
        "discord_webhook": "",
        "email_enabled": True,
        "smtp_server": "smtp.sentinelle.local",
        "smtp_port": 587,
        "email_recipient": "soc@sentinelle.local",
        "email_use_tls": True,
    }
    resp_save = client.put("/api/v1/admin/notifications/config", json=payload, headers=headers)
    assert resp_save.status_code == 200

    resp_load = client.get("/api/v1/admin/notifications/config", headers=headers)
    assert resp_load.status_code == 200
    loaded = resp_load.json()
    assert loaded["telegram_enabled"] is True
    # Le secret n'est jamais renvoyé en clair : seul son état est exposé
    assert loaded["telegram_token"] == ""
    assert loaded["telegram_token_set"] is True
    assert loaded["email_recipient"] == "soc@sentinelle.local"


def test_real_dashboard_telemetry_series_and_refresh():
    """Vérifie la présence des séries temporelles réelles dans le résumé du Dashboard."""
    headers = _get_admin_headers()

    resp_refresh = client.post("/api/v1/dashboard/refresh", headers=headers)
    assert resp_refresh.status_code == 200
    data = resp_refresh.json()
    assert "telemetry_series" in data
    assert len(data["telemetry_series"]) >= 4
    first_pt = data["telemetry_series"][0]
    assert "cpu_actual" in first_pt
    assert "ram_actual" in first_pt
    assert "disk_actual" in first_pt
    assert "threshold" in first_pt

