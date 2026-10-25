"""Tests unitaires et d'intégration du module NetDevOps & Audit CIS Benchmark."""
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.modules.netdevops.service import (
    _load_cis_rules,
    _audit_config,
    _save_backup,
    _diff_configs,
    get_available_devices,
    run_audit,
)

client = TestClient(app)


def test_cis_rules_yaml_loading():
    """Vérifie le bon chargement et la structure du fichier YAML cis_rules.yaml."""
    rules = _load_cis_rules()
    assert len(rules) >= 10, "Le catalogue CIS doit contenir au moins 10 règles."
    for rule in rules:
        assert "id" in rule
        assert "title" in rule
        assert "severity" in rule
        assert rule["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        assert "pattern" in rule or "regex_forbidden" in rule
        assert "remediation" in rule


def test_cis_audit_hardened_vs_vulnerable():
    """Vérifie que l'audit discrimine correctement un équipement durci d'un équipement vulnérable."""
    hardened_cfg = """
    hostname HARDENED-SW
    service password-encryption
    enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
    ip ssh version 2
    no ip http server
    ntp server 192.168.1.1
    service timestamps log datetime
    logging host 192.168.1.254
    logging trap informational
    banner motd ^C Authorized access only ^C
    no ip source-route
    interface GigabitEthernet0/1
     no cdp enable
     ip access-group ACL-WAN in
    line vty 0 4
     exec-timeout 10 0
     transport input ssh
    """
    report_hardened = _audit_config("HARDENED-SW", hardened_cfg)
    assert report_hardened["score"] >= 80.0
    assert report_hardened["failed_rules"] < report_hardened["passed_rules"]

    vulnerable_cfg = """
    hostname VULN-RTR
    enable password cisco
    ip http server
    snmp-server community public ro
    snmp-server community private rw
    line vty 0 4
     transport input telnet
    """
    report_vuln = _audit_config("VULN-RTR", vulnerable_cfg)
    assert report_vuln["score"] < 40.0
    # Vérification des violations critiques détectées
    violation_ids = [v["id"] for v in report_vuln["violations"]]
    assert "CIS-1.2" in violation_ids  # enable password
    assert "CIS-1.4" in violation_ids  # telnet
    assert "CIS-1.6" in violation_ids  # ip http server
    assert "CIS-5.2" in violation_ids  # snmp public


def test_backup_and_diff_generation(tmp_path):
    """Vérifie le versioning des configurations et le calcul du diff unifié."""
    cfg_v1 = "hostname RTR-TEST\nservice password-encryption\n"
    cfg_v2 = "hostname RTR-TEST\nservice password-encryption\nip ssh version 2\n"

    # Sauvegarde v1 puis v2
    _save_backup("RTR-TEST-UNIT", cfg_v1)
    _save_backup("RTR-TEST-UNIT", cfg_v2)

    diff = _diff_configs("RTR-TEST-UNIT", index_a=1, index_b=0)
    assert "error" not in diff
    assert "+ip ssh version 2" in diff["diff"]
    assert diff["changed_lines"] >= 1


@pytest.mark.asyncio
async def test_run_audit_async_service():
    """Vérifie l'exécution du service complet asynchrone avec fallback LLM."""
    report = await run_audit("SW-CORE-01")
    assert report["device_id"] == "SW-CORE-01"
    assert "score" in report
    assert "violations" in report
    assert "llm_recommendations" in report
    assert len(report["llm_recommendations"]) > 0

    with pytest.raises(ValueError):
        await run_audit("INCONNU-DEVICE-999")


def test_api_netdevops_endpoints():
    """Vérifie les points de terminaison REST de l'API FastAPI."""
    # 1. Liste des équipements
    resp_devices = client.get("/api/v1/netdevops/devices")
    assert resp_devices.status_code == 200
    devices = resp_devices.json()
    assert len(devices) >= 4
    assert any(d["id"] == "SW-CORE-01" for d in devices)

    # 2. Lancement audit
    resp_audit = client.post("/api/v1/netdevops/audit/SW-CORE-01")
    assert resp_audit.status_code == 200
    data = resp_audit.json()
    assert data["device_id"] == "SW-CORE-01"
    assert "score" in data
    assert "violations" in data

    # 3. Équipement inexistant
    resp_bad = client.post("/api/v1/netdevops/audit/INEXISTANT-DEV")
    assert resp_bad.status_code == 404

    # 4. Historique de sauvegardes
    resp_backups = client.get("/api/v1/netdevops/backups/SW-CORE-01")
    assert resp_backups.status_code == 200
    assert isinstance(resp_backups.json(), list)
