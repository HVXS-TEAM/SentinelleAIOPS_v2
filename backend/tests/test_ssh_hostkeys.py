"""Vérification des clés d'hôte SSH : TOFU, épinglage, mode strict et API d'administration.

Les connexions sont réelles (serveur Paramiko local sur 127.0.0.1, port éphémère) :
on teste le comportement effectif de paramiko, pas une simulation.
"""
import socket
import threading
from pathlib import Path

import paramiko
import pytest
from fastapi.testclient import TestClient

from backend.app.core import config as cfg
from backend.app.core import ssh_trust
from backend.app.main import app

client = TestClient(app)
ROOT = Path(__file__).resolve().parents[2]


class _Serveur(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"


class ServeurSSH:
    """Serveur SSH minimal : accepte une authentification par mot de passe puis se ferme."""

    def __init__(self, cle: paramiko.PKey):
        self.cle = cle
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._boucle, daemon=True).start()

    def _boucle(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(self.cle)
            try:
                t.start_server(server=_Serveur())
            except Exception:
                pass

    def fermer(self):
        self._stop = True
        self.sock.close()


def _connecter(port: int):
    ssh = ssh_trust.new_ssh_client()
    try:
        ssh.connect("127.0.0.1", port=port, username="u", password="p",
                    timeout=5, allow_agent=False, look_for_keys=False)
    finally:
        ssh.close()


@pytest.fixture()
def known_hosts(monkeypatch, tmp_path):
    chemin = tmp_path / "ssh_known_hosts"
    monkeypatch.setattr(cfg, "SSH_KNOWN_HOSTS_FILE", chemin)
    return chemin


@pytest.fixture()
def serveur():
    s = ServeurSSH(paramiko.RSAKey.generate(2048))
    yield s
    s.fermer()


# ── TOFU et épinglage ────────────────────────────────────────────────────────

def test_premiere_connexion_enregistre_la_cle(known_hosts, serveur):
    _connecter(serveur.port)
    lignes = ssh_trust.list_known_hosts()
    assert len(lignes) == 1
    assert lignes[0]["hote"] == f"[127.0.0.1]:{serveur.port}"
    assert lignes[0]["empreinte"].startswith("SHA256:")
    assert known_hosts.exists()


def test_cle_connue_acceptee_sans_nouvel_enregistrement(known_hosts, serveur):
    _connecter(serveur.port)
    avant = known_hosts.read_text()
    _connecter(serveur.port)
    assert known_hosts.read_text() == avant


def test_cle_modifiee_toujours_refusee(known_hosts, serveur):
    _connecter(serveur.port)
    serveur.cle = paramiko.RSAKey.generate(2048)  # l'équipement présente une autre clé
    with pytest.raises(paramiko.BadHostKeyException):
        _connecter(serveur.port)


def test_cle_modifiee_refusee_meme_en_mode_non_strict(known_hosts, serveur, monkeypatch):
    monkeypatch.setattr(cfg.settings, "SSH_STRICT_HOST_KEYS", False)
    _connecter(serveur.port)
    serveur.cle = paramiko.RSAKey.generate(2048)
    with pytest.raises(paramiko.SSHException):
        _connecter(serveur.port)


def test_mode_strict_refuse_un_hote_inconnu(known_hosts, serveur, monkeypatch):
    monkeypatch.setattr(cfg.settings, "SSH_STRICT_HOST_KEYS", True)
    with pytest.raises(ssh_trust.UnknownHostKeyError):
        _connecter(serveur.port)
    assert not known_hosts.exists() or ssh_trust.list_known_hosts() == []


def test_mode_strict_accepte_un_hote_preenregistre(known_hosts, serveur, monkeypatch):
    _connecter(serveur.port)  # enregistrement TOFU
    monkeypatch.setattr(cfg.settings, "SSH_STRICT_HOST_KEYS", True)
    _connecter(serveur.port)


def test_oublier_puis_reepingler_nouvelle_cle(known_hosts, serveur):
    _connecter(serveur.port)
    serveur.cle = paramiko.RSAKey.generate(2048)
    assert ssh_trust.forget_host("127.0.0.1", serveur.port) == 1
    _connecter(serveur.port)  # nouvelle clé épinglée
    assert len(ssh_trust.list_known_hosts()) == 1


def test_oublier_hote_inconnu_retourne_zero(known_hosts):
    assert ssh_trust.forget_host("10.9.9.9") == 0


def test_nom_de_cle_port_22_et_autre_port():
    assert ssh_trust.host_key_name("10.0.0.1", 22) == "10.0.0.1"
    assert ssh_trust.host_key_name("10.0.0.1", 2222) == "[10.0.0.1]:2222"


# ── Plus d'AutoAddPolicy dans le code ────────────────────────────────────────

def test_autoaddpolicy_n_est_plus_utilisee():
    fautifs = [
        str(p.relative_to(ROOT))
        for p in (ROOT / "backend" / "app").rglob("*.py")
        if "AutoAddPolicy()" in p.read_text(encoding="utf-8")
    ]
    assert not fautifs, f"AutoAddPolicy encore utilisée dans : {fautifs}"


def test_les_services_n_instancient_plus_sshclient_directement():
    for rel in ("modules/netdevops/service.py", "modules/parc/ssh_service.py", "modules/parc/service.py"):
        texte = (ROOT / "backend" / "app" / rel).read_text(encoding="utf-8")
        assert "paramiko.SSHClient()" not in texte, rel


def test_parametre_strict_documente_et_desactive_par_defaut():
    assert cfg.Settings.model_fields["SSH_STRICT_HOST_KEYS"].default is False


# ── API d'administration ─────────────────────────────────────────────────────

URL = "/api/v1/admin/ssh/known-hosts"


def test_api_sans_jeton_401():
    assert client.get(URL).status_code == 401
    assert client.delete(f"{URL}/10.0.0.1").status_code == 401


def test_api_refusee_au_technicien_et_visiteur(tech_headers, visiteur_headers):
    for h in (tech_headers, visiteur_headers):
        assert client.get(URL, headers=h).status_code == 403
        assert client.delete(f"{URL}/10.0.0.1", headers=h).status_code == 403


def test_api_admin_liste_et_oublie(known_hosts, serveur, admin_headers):
    _connecter(serveur.port)
    lignes = client.get(URL, headers=admin_headers).json()
    assert any(l["hote"] == f"[127.0.0.1]:{serveur.port}" for l in lignes)
    assert all("PRIVATE" not in str(l) for l in lignes)

    r = client.delete(f"{URL}/127.0.0.1?port={serveur.port}", headers=admin_headers)
    assert r.status_code == 200 and r.json()["cles_supprimees"] == 1
    assert client.delete(f"{URL}/127.0.0.1?port={serveur.port}", headers=admin_headers).status_code == 404

