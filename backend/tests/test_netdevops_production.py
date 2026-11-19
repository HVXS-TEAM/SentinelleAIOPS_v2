"""NetDevOps en production : jamais de configuration inventée, application réelle ou erreur."""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.modules.netdevops import service as nd

client = TestClient(app)


def test_aucune_configuration_inventee_dans_le_code():
    interdits = ("_SIMULATED_CONFIGS", "EMULATED_CLI", "simulate_snmp_discovery", "simulate_bruteforce_attack",
                 "simulate_disk_stress")
    racine = Path(__file__).resolve().parents[1] / "app"
    trouves = [
        f"{p.relative_to(racine)}:{mot}"
        for p in racine.rglob("*.py")
        for mot in interdits
        if mot in p.read_text(encoding="utf-8")
    ]
    assert not trouves, f"Code de simulation encore présent : {trouves}"


def test_liste_sans_audit_ne_fabrique_aucun_score(tech_headers):
    devices = client.get("/api/v1/netdevops/devices", headers=tech_headers).json()
    noms = {d["id"] for d in devices}
    assert not {"RTR-EDGE-01", "FW-PERIMETER-01", "AP-WIFI-01"} & noms  # plus de gabarits inventés
    for d in devices:
        if d["config_status"] == "jamais auditée":
            assert d["cis_score"] is None and d["findings"] is None


def test_equipement_injoignable_sans_sauvegarde_donne_409(tech_headers, faux_cisco):
    faux_cisco.injoignable = True
    nd._backup_path("SRV-DB-01").unlink(missing_ok=True)
    r = client.post("/api/v1/netdevops/audit/SRV-DB-01", headers=tech_headers)
    assert r.status_code == 409
    assert "SSH" in r.json()["detail"] or "Aucun identifiant" in r.json()["detail"]


def test_injoignable_avec_sauvegarde_reelle_indique_la_provenance(tech_headers, faux_cisco):
    ok = client.post("/api/v1/netdevops/audit/SW-CORE-01", headers=tech_headers)
    assert ok.status_code == 200 and ok.json()["config_source"] == "live"
    faux_cisco.injoignable = True
    r = client.post("/api/v1/netdevops/audit/SW-CORE-01", headers=tech_headers)
    assert r.status_code == 200
    assert r.json()["config_source"].startswith("sauvegarde")


def test_remediation_impossible_ne_modifie_rien(admin_headers, faux_cisco):
    client.post("/api/v1/netdevops/audit/SW-CORE-01", headers=admin_headers)  # une sauvegarde réelle existe
    avant = len(nd._get_backups("SW-CORE-01"))
    faux_cisco.injoignable = True
    r = client.post("/api/v1/netdevops/remediate/SW-CORE-01",
                    json={"remediation_snippet": "no ip http server", "rule_id": "CIS-1.6"}, headers=admin_headers)
    assert r.status_code == 409
    assert len(nd._get_backups("SW-CORE-01")) == avant
    assert faux_cisco.pushes == []


def test_remediation_applique_puis_relit_la_configuration_reelle(admin_headers, faux_cisco):
    r = client.post("/api/v1/netdevops/remediate/SW-CORE-01",
                    json={"remediation_snippet": "no ip http server", "rule_id": "CIS-1.6"}, headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["ssh_mode"] == "REAL_SSH_APPLIED"
    assert "ip http server" not in [l.strip() for l in faux_cisco.config.splitlines()]
    assert all(v["id"] != "CIS-1.6" for v in r.json()["audit"]["violations"])


def test_restauration_n_est_pas_presentee_comme_deployee(admin_headers, faux_cisco):
    client.post("/api/v1/netdevops/audit/SW-CORE-01", headers=admin_headers)
    r = client.post("/api/v1/netdevops/restore/SW-CORE-01", json={"backup_index": 0}, headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["deployed"] is False


class _FauxCanal:
    def __init__(self, rejet: bool):
        self.rejet, self.envoyes, self._buf = rejet, [], b""

    def settimeout(self, _): ...

    def send(self, texte):
        self.envoyes.append(texte.strip())
        self._buf = (b"% Invalid input detected\n" if self.rejet and texte.startswith("bad") else b"ok\n")

    def recv_ready(self):
        return bool(self._buf)

    def recv(self, _):
        out, self._buf = self._buf, b""
        return out


class _FauxSSH:
    def __init__(self, canal): self.canal = canal
    def invoke_shell(self): return self.canal
    def close(self): ...


def _eq():
    return {"id": 1, "nom": "SW-CORE-01", "ip": "192.168.1.1", "creds": "x"}


def test_push_ios_envoie_configure_terminal_et_write_memory(monkeypatch):
    canal = _FauxCanal(rejet=False)
    monkeypatch.setattr(nd, "_open_ssh", lambda eq, timeout=6.0: _FauxSSH(canal))
    monkeypatch.setattr("time.sleep", lambda _: None)
    nd._push_config_ios(_eq(), "no ip http server\nservice password-encryption")
    assert canal.envoyes == ["terminal length 0", "configure terminal", "no ip http server",
                             "service password-encryption", "end", "write memory"]


def test_push_ios_refuse_si_l_equipement_rejette_une_commande(monkeypatch):
    canal = _FauxCanal(rejet=True)
    monkeypatch.setattr(nd, "_open_ssh", lambda eq, timeout=6.0: _FauxSSH(canal))
    monkeypatch.setattr("time.sleep", lambda _: None)
    with pytest.raises(nd.ConfigUnavailableError, match="rejeté"):
        nd._push_config_ios(_eq(), "bad command")
    assert "write memory" not in canal.envoyes


def test_regle_http_ne_signale_pas_un_equipement_deja_durci():
    """« no ip http server » (état durci, tel que l'affiche IOS) ne doit pas être vu comme une violation."""
    durci = nd._audit_config("X", "hostname X\nno ip http server\nno enable password\n")
    vulnerable = nd._audit_config("X", "hostname X\nip http server\nenable password cisco\n")
    assert "CIS-1.6" not in [v["id"] for v in durci["violations"]]
    assert {"CIS-1.6", "CIS-1.2"} <= {v["id"] for v in vulnerable["violations"]}


def test_les_violations_exposent_des_commandes_applicables_ou_aucune():
    """Une règle sans paramètre propose des commandes IOS exactes ; sinon aucune commande (correction manuelle)."""
    rapport = nd._audit_config("X", "hostname X\nip http server\nenable password cisco\n")
    par_id = {v["id"]: v for v in rapport["violations"]}
    assert par_id["CIS-1.6"]["remediation_commands"] == "no ip http server"
    assert par_id["CIS-1.2"]["remediation_commands"] == ""  # exige un hash : manuel
    for regle in nd._load_cis_rules():
        for ligne in regle.get("remediation_commands", "").splitlines():
            assert "<" not in ligne and ">" not in ligne, f"{regle['id']} : paramètre non résolu"
