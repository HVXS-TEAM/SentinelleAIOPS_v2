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


def _faux_scan(monkeypatch, appareils):
    """Remplace uniquement la collecte réseau (ping/ARP) : le rapprochement avec le parc reste réel."""
    monkeypatch.setattr(
        ParcService, "scan_real_network",
        staticmethod(lambda db, ip_prefix=None: {"subnet": "198.51.100.0/24", "local_host": {}, "devices_count": len(appareils),
                                               "devices": appareils, "scan_duration_ms": 1}),
    )


def test_decouverte_reseau_alerte_sur_equipement_non_repertorie(monkeypatch):
    """Un équipement actif absent du parc lève une alerte CRITICAL (une seule), sans être ajouté au parc."""
    inconnu = {"ip": "198.51.100.77", "mac": "AA:BB:CC:00:11:22", "hostname": "inconnu-77", "already_in_parc": False}
    connu = {"ip": "192.168.1.1", "mac": None, "hostname": "SW-CORE-01", "already_in_parc": True}
    _faux_scan(monkeypatch, [inconnu, connu])
    db = SessionLocal()
    try:
        res = ParcService.discover_network(db, "198.51.100.0/24")
        assert res["nouveaux_detectes"] == 1
        assert res["rogue_device"]["ip"] == "198.51.100.77"
        assert set(res["equipements_actifs"]) == {"198.51.100.77", "192.168.1.1"}
        assert db.query(Equipement).filter(Equipement.ip == "198.51.100.77").first() is None

        ParcService.discover_network(db, "198.51.100.0/24")  # second balayage : pas de doublon d'alerte
        alertes = db.query(Alerte).filter(Alerte.titre.like("%198.51.100.77%"), Alerte.statut == "Active").all()
        assert len(alertes) == 1 and alertes[0].severite == "CRITICAL"
    finally:
        db.close()


def test_decouverte_reseau_sans_inconnu_ne_cree_aucune_alerte(monkeypatch):
    _faux_scan(monkeypatch, [{"ip": "192.168.1.1", "mac": None, "hostname": "SW-CORE-01", "already_in_parc": True}])
    db = SessionLocal()
    try:
        avant = db.query(Alerte).count()
        res = ParcService.discover_network(db, "192.168.1.0/24")
        assert res["nouveaux_detectes"] == 0 and res["rogue_device"] is None
        assert db.query(Alerte).count() == avant
    finally:
        db.close()


class _FauxSSH:
    def __init__(self, panne=None):
        self.panne = panne

    def connect(self, **kw):
        if self.panne:
            raise self.panne

    def exec_command(self, cmd, timeout=None):
        import io
        class _Flux(io.BytesIO):
            class channel:
                @staticmethod
                def recv_exit_status():
                    return 0
        return None, _Flux(b"hostname SW-REEL\n"), _Flux(b"")

    def close(self):
        pass


def test_terminal_equipement_distant_utilise_le_vrai_ssh(monkeypatch):
    from backend.app.modules.parc import ssh_service
    from backend.app.modules.parc.ssh_service import SSHExecutionService
    monkeypatch.setattr(ssh_service, "new_ssh_client", lambda: _FauxSSH())
    res = SSHExecutionService.execute(ip="198.51.100.10", command="show run", username="u", password="p", device_name="SW-REEL")
    assert res["mode"] == "REAL_SSH" and res["exit_code"] == 0
    assert "hostname SW-REEL" in res["output"]


def test_terminal_equipement_injoignable_renvoie_une_erreur_et_rien_d_invente(monkeypatch):
    from backend.app.modules.parc import ssh_service
    from backend.app.modules.parc.ssh_service import SSHExecutionService
    monkeypatch.setattr(ssh_service, "new_ssh_client", lambda: _FauxSSH(panne=TimeoutError("timed out")))
    res = SSHExecutionService.execute(ip="198.51.100.10", command="show version", device_name="SW-HS")
    assert res["mode"] == "SSH_ERROR" and res["exit_code"] == 255
    assert "Cisco IOS" not in res["output"] and "TimeoutError" in res["output"]


def test_terminal_hote_local_utilise_le_diagnostic_reel():
    from backend.app.modules.parc.ssh_service import SSHExecutionService
    res = SSHExecutionService.execute(ip="127.0.0.1", command="arp -a", device_name="HOTE")
    assert res["mode"] == "REAL_HOST_PROBE"


def test_terminal_endpoint_remonte_l_echec_ssh(monkeypatch):
    from backend.app.modules.parc import ssh_service
    monkeypatch.setattr(ssh_service, "new_ssh_client", lambda: _FauxSSH(panne=ConnectionRefusedError("refused")))
    headers = {"Authorization": f"Bearer {get_auth_token('admin')}"}
    resp = client.post("/api/v1/parc/ssh/execute", headers=headers,
                       json={"ip": "198.51.100.10", "command": "show version", "device_name": "SW-HS"})
    assert resp.status_code == 200
    assert resp.json()["mode"] == "SSH_ERROR" and resp.json()["exit_code"] == 255


def test_scan_and_auto_enroll_enroles_new_devices(monkeypatch):
    """Vérifie que l'auto-découverte enrôle automatiquement les équipements du réseau et crée une alerte."""
    db = SessionLocal()
    test_device = {
        "ip": "192.0.2.77",
        "mac": "AA:BB:CC:DD:EE:77",
        "hostname": "ROUTEUR-AUTO-TEST",
        "type": "Routeur / Passerelle",
        "os": "Test OS",
        "open_ports": [80],
        "already_in_parc": False,
    }
    monkeypatch.setattr(ParcService, "scan_real_network", lambda _db: {"devices": [test_device]})

    res = ParcService.scan_and_auto_enroll(db)
    assert res["new_enrolled_count"] == 1

    # Vérifier que l'équipement a été inséré
    eq = db.query(Equipement).filter(Equipement.ip == "192.0.2.77").first()
    assert eq is not None
    assert eq.nom == "ROUTEUR-AUTO-TEST"
    assert eq.groupe == "LAN Découvert"

    # Vérifier qu'une alerte informative d'auto-découverte a été créée
    alerte = db.query(Alerte).filter(Alerte.module_origine == "Parc", Alerte.equipement_id == eq.id).first()
    assert alerte is not None
    assert alerte.severite == "INFO"
    assert "ROUTEUR-AUTO-TEST" in alerte.titre

    # Nettoyage
    db.delete(alerte)
    db.delete(eq)
    db.commit()
    db.close()




