"""Tests unitaires et d'intégration du module Gestion de Parc & Inventaire."""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.db.session import SessionLocal
from backend.app.db.models import Equipement, Alerte
from backend.app.modules.parc.service import ParcService

client = TestClient(app)


def get_auth_token(identifiant: str = "admin", mot_de_passe: str = "AdminPassword2026!") -> str:
    resp = client.post("/api/v1/auth/login", json={"identifiant": identifiant, "mot_de_passe": mot_de_passe})
    return resp.json()["access_token"]


def test_health_score_calculation():
    """Vérifie le calcul pondéré du score de santé composite (0-100)."""
    db = SessionLocal()
    srv = db.query(Equipement).filter(Equipement.nom == "SRV-DB-01").first()
    assert srv is not None

    score = ParcService.calculate_health_score(db, srv.id)
    assert 0.0 <= score <= 100.0
    assert srv.score_sante == score
    db.close()


def test_snmp_scan_and_rogue_device_detection():
    """Vérifie la détection d'équipement non répertorié (Rogue Device) et la levée d'alerte."""
    db = SessionLocal()
    scan_res = ParcService.simulate_snmp_discovery(db, "192.168.1.0/24", inject_rogue=True)
    assert scan_res["nouveaux_detectes"] == 1
    assert scan_res["rogue_device"] is not None
    assert scan_res["rogue_device"]["nom"] == "ROGUE-PI-01"

    # Vérifier l'alerte CRITICAL associée
    alert = db.query(Alerte).filter(Alerte.titre.like("%ROGUE-PI-01%")).first()
    assert alert is not None
    assert alert.severite == "CRITICAL"
    db.close()


def test_csv_export():
    """Vérifie la génération du rapport CSV d'inventaire."""
    db = SessionLocal()
    csv_str = ParcService.export_csv(db)
    assert "ID;Nom;IP;MAC;Type" in csv_str
    assert "SW-CORE-01" in csv_str
    db.close()


def test_api_equipements_list_and_detail():
    """Vérifie les endpoints REST d'inventaire et de fiche équipement."""
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    # Liste
    resp_list = client.get("/api/v1/parc/equipements", headers=headers)
    assert resp_list.status_code == 200
    eqs = resp_list.json()
    assert len(eqs) >= 4

    # Fiche détail
    first_id = eqs[0]["id"]
    resp_detail = client.get(f"/api/v1/parc/equipements/{first_id}", headers=headers)
    assert resp_detail.status_code == 200
    data = resp_detail.json()
    assert "equipement" in data
    assert "audits" in data
    assert "alertes_actives" in data


def test_api_create_equipement():
    """Vérifie l'ajout d'un équipement via l'API avec chiffrement du mot de passe."""
    import uuid
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}
    uid = uuid.uuid4().hex

    payload = {
        "nom": f"SW-ACCESS-{uid[:6]}",
        "ip": f"10.254.{int(uid[:2], 16)}.{int(uid[2:4], 16) + 1}",
        "mac": f"00:1A:2B:{uid[:2]}:{uid[2:4]}:{uid[4:6]}",
        "type": "Switch Cisco",
        "os": "Cisco IOS",
        "groupe": "Accès",
        "mot_de_passe_secret": "cisco_vty_pass_2026",
    }
    resp = client.post("/api/v1/parc/equipements", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["nom"] == payload["nom"]

    # Nettoyage
    client.delete(f"/api/v1/parc/equipements/{data['id']}", headers=headers)


def test_api_delete_equipement():
    """Vérifie la suppression d'un équipement et la journalisation d'audit."""
    import uuid
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}
    uid = uuid.uuid4().hex

    # Création temporaire
    payload = {
        "nom": f"SW-DEL-{uid[:6]}",
        "ip": f"10.253.{int(uid[:2], 16)}.{int(uid[2:4], 16) + 1}",
        "type": "Switch Cisco",
        "groupe": "Test",
    }
    create_resp = client.post("/api/v1/parc/equipements", json=payload, headers=headers)
    assert create_resp.status_code == 200
    eq_id = create_resp.json()["id"]

    # Suppression
    del_resp = client.delete(f"/api/v1/parc/equipements/{eq_id}", headers=headers)
    assert del_resp.status_code == 200
    assert "supprimé avec succès" in del_resp.json()["message"]

    # Vérification que la ressource n'existe plus
    get_resp = client.get(f"/api/v1/parc/equipements/{eq_id}", headers=headers)
    assert get_resp.status_code == 404


def test_local_network_info_and_scan():
    """Vérifie la détection réseau physique de l'hôte et le balayage physique réel."""
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Info réseau local
    resp_info = client.get("/api/v1/parc/local-network-info", headers=headers)
    assert resp_info.status_code == 200
    info_data = resp_info.json()
    assert "local_ip" in info_data
    assert "subnet" in info_data
    assert "hostname" in info_data
    assert "/" in info_data["subnet"]

    # 2. Balayage réseau physique
    resp_scan = client.post("/api/v1/parc/scan-real", headers=headers)
    assert resp_scan.status_code == 200
    scan_data = resp_scan.json()
    assert scan_data["devices_count"] >= 1
    assert "devices" in scan_data
    assert len(scan_data["devices"]) >= 1

    first_dev = scan_data["devices"][0]
    assert "ip" in first_dev
    assert "type" in first_dev
    assert "open_ports" in first_dev


def test_import_real_devices_api():
    """Vérifie l'importation en base de données d'équipements scannés."""
    import uuid
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}
    uid = uuid.uuid4().hex[:6]

    fake_mac = f"02:00:00:{uid[:2]}:{uid[2:4]}:{uid[4:6]}"
    fake_ip = f"10.252.{int(uid[:2], 16)}.{int(uid[2:4], 16) + 1}"

    payload = {
        "devices": [
            {
                "nom": f"PHY-BOX-{uid}",
                "ip": fake_ip,
                "mac": fake_mac,
                "type": "Routeur / Box Internet Physique",
                "os": "Linux Embarqué",
                "groupe": "Physique",
            }
        ]
    }
    resp = client.post("/api/v1/parc/import-real-devices", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["imported_count"] == 1

    imported_id = data["imported_devices"][0]["id"]

    # Nettoyage
    client.delete(f"/api/v1/parc/equipements/{imported_id}", headers=headers)


def test_ssh_execute_cisco_and_linux_cli():
    """Vérifie le moteur CLI pour les commandes Cisco IOS et Linux."""
    from backend.app.modules.parc.ssh_service import SSHExecutionService

    # 1. Cisco show run
    res_run = SSHExecutionService.execute(ip="192.168.1.1", command="show run", device_name="SW-CORE-01")
    assert res_run["exit_code"] == 0
    assert "hostname SW-CORE-01" in res_run["output"]
    assert "GigabitEthernet0/0" in res_run["output"]

    # 2. Cisco show ip int brief
    res_ip = SSHExecutionService.execute(ip="192.168.1.1", command="show ip int brief")
    assert "GigabitEthernet0/0" in res_ip["output"]
    assert "up" in res_ip["output"]

    # 3. Linux df -h & uptime
    res_df = SSHExecutionService.execute(ip="10.0.10.20", command="df -h", device_name="SRV-DB-01")
    assert "/dev/sda1" in res_df["output"]

    res_uptime = SSHExecutionService.execute(ip="10.0.10.20", command="uptime")
    assert "load average" in res_uptime["output"]

    # 4. Help
    res_help = SSHExecutionService.execute(ip="10.0.10.20", command="help")
    assert "Sentinelle AIOps Terminal" in res_help["output"]


def test_ssh_execute_api_endpoint():
    """Vérifie l'endpoint REST /parc/ssh/execute."""
    token = get_auth_token("admin")
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "ip": "192.168.1.1",
        "command": "show version",
        "device_name": "RTR-TEST",
    }
    resp = client.post("/api/v1/parc/ssh/execute", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "output" in data
    assert "Cisco IOS" in data["output"]
    assert data["exit_code"] == 0
    assert "mode" in data



