"""Configuration Pytest pour Sentinelle AIOps v2.

Fournit le support natif des fonctions de test asynchrones (@pytest.mark.asyncio)
via la bibliothèque standard asyncio lorsque pytest-asyncio n'est pas installé.
"""
import asyncio
import atexit
import inspect
import os
import shutil
import tempfile

import pytest

# ── Isolation des données de test ────────────────────────────────────────────
# DOIT s'exécuter avant tout import de backend.app : la configuration lit ces variables à l'import.
# Base SQLite, sauvegardes PRA, sauvegardes de configuration, secrets et notifications vivent dans
# un dossier temporaire supprimé en fin de session : les tests ne touchent plus ni la base de
# développement (backend/sentinelle.db) ni aucun fichier suivi par git.
_TEST_DATA_DIR = tempfile.mkdtemp(prefix="sentinelle_tests_")
os.environ["SENTINELLE_DATA_DIR"] = _TEST_DATA_DIR
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DATA_DIR.replace(os.sep, '/')}/sentinelle.db"
atexit.register(shutil.rmtree, _TEST_DATA_DIR, ignore_errors=True)


def pytest_configure(config: pytest.Config) -> None:
    """Déclare le marqueur asyncio pour éviter tout avertissement PytestUnknownMarkWarning."""
    config.addinivalue_line("markers", "asyncio: exécute un test asynchrone via asyncio.run()")


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function) -> bool | None:
    """Exécute les coroutines de test dans une boucle d'événements asyncio isolée."""
    testfunction = pyfuncitem.obj
    if inspect.iscoroutinefunction(testfunction):
        funcargs = pyfuncitem.funcargs
        testargs = {arg: funcargs[arg] for arg in pyfuncitem._fixtureinfo.argnames}
        asyncio.run(testfunction(**testargs))
        return True
    return None


# ── Données de test (base temporaire uniquement) ─────────────────────────────
# L'application ne fournit AUCUNE donnée de départ. Ces comptes et équipements existent seulement
# dans la base temporaire de la session de test, créés ici explicitement.

TEST_ACCOUNTS = [
    ("admin", "admin@test.local", "Administrateur Test", "AdminPassword2026!", "Administrateur"),
    ("tech", "tech@test.local", "Technicien Test", "TechPassword2026!", "Technicien"),
    ("visiteur", "visiteur@test.local", "Visiteur Test", "VisiteurPassword2026!", "Visiteur"),
]

TEST_EQUIPEMENTS = [
    ("SW-CORE-01", "192.168.1.1", "00:1A:2B:3C:4D:01", "Switch Cisco", "Cisco IOS-XE", "cisco:cisco123"),
    ("SRV-APP-01", "192.168.1.10", "00:50:56:A1:B2:10", "Serveur Linux", "Debian GNU/Linux 12", "debian:labo2026!"),
    ("SRV-DB-01", "192.168.1.20", "00:50:56:A1:B2:20", "Serveur Linux", "Ubuntu 22.04 LTS", "postgres:dbsecret2026"),
]


@pytest.fixture(scope="session", autouse=True)
def _donnees_de_test() -> None:
    """Crée les comptes et équipements de test dans la base temporaire."""
    from backend.app.main import app  # noqa: F401  (crée les tables au démarrage)
    from backend.app.db.session import SessionLocal
    from backend.app.db.models import User, Equipement
    from backend.app.core.security import get_password_hash, encrypt_secret

    with SessionLocal() as db:
        for ident, email, nom, pwd, role in TEST_ACCOUNTS:
            if not db.query(User).filter_by(identifiant=ident).first():
                db.add(User(identifiant=ident, email=email, nom_complet=nom,
                            hash_mot_de_passe=get_password_hash(pwd), role=role,
                            est_actif=True, mfa_active=False))
        for nom, ip, mac, typ, os_, creds in TEST_EQUIPEMENTS:
            if not db.query(Equipement).filter_by(nom=nom).first():
                db.add(Equipement(nom=nom, ip=ip, mac=mac, type=typ, os=os_,
                                  identifiants_chiffres=encrypt_secret(creds),
                                  statut_collecte="OK", score_sante=100.0))
        db.commit()


# ── Authentification partagée pour les tests d'API (RBAC) ────────────────────

def _login_headers(identifiant: str, mot_de_passe: str) -> dict[str, str]:
    """Ouvre une session réelle via /auth/login et retourne l'en-tête Bearer."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    resp = TestClient(app).post(
        "/api/v1/auth/login",
        json={"identifiant": identifiant, "mot_de_passe": mot_de_passe},
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.fixture(autouse=True)
def _inscription_ouverte(monkeypatch) -> None:
    """L'inscription publique est fermée par défaut en production ; les tests qui la
    couvrent l'ouvrent explicitement (un test peut la refermer lui-même)."""
    from backend.app.core.config import settings
    monkeypatch.setattr(settings, "ALLOW_SELF_REGISTRATION", True)


@pytest.fixture(scope="session")
def admin_headers() -> dict[str, str]:
    """En-têtes d'un Administrateur (compte de test)."""
    return _login_headers("admin", "AdminPassword2026!")


@pytest.fixture(scope="session")
def tech_headers() -> dict[str, str]:
    """En-têtes d'un Technicien (compte de test)."""
    return _login_headers("tech", "TechPassword2026!")


@pytest.fixture(scope="session")
def visiteur_headers() -> dict[str, str]:
    """En-têtes d'un Visiteur en lecture seule (compte de test)."""
    return _login_headers("visiteur", "VisiteurPassword2026!")



# ── Faux équipement Cisco IOS pour les tests NetDevOps ────────────────────────
# L'application n'invente jamais de configuration : elle lit l'équipement en SSH. Les tests
# remplacent donc la couche SSH par un équipement simulé, déclaré ici et nulle part ailleurs.

CONFIG_IOS_FAIBLE = """\
version 15.2
hostname SW-CORE-01
enable password cisco
ip http server
snmp-server community public ro
line vty 0 4
 transport input telnet
end
"""


class FauxCisco:
    """Équipement IOS en mémoire : sa configuration change quand on y « pousse » des commandes."""

    def __init__(self) -> None:
        self.config = CONFIG_IOS_FAIBLE
        self.pushes: list[str] = []
        self.injoignable = False

    def fetch(self, eq):
        from backend.app.modules.netdevops.service import ConfigUnavailableError
        if self.injoignable:
            raise ConfigUnavailableError(f"Connexion SSH impossible vers {eq['nom']}.")
        return self.config

    def push(self, eq, commands):
        from backend.app.modules.netdevops.service import ConfigUnavailableError, _apply_remediation_to_config
        if self.injoignable:
            raise ConfigUnavailableError(f"Connexion SSH impossible vers {eq['nom']}.")
        self.pushes.append(commands)
        self.config = _apply_remediation_to_config(self.config, commands)
        lignes = [l.strip() for l in self.config.splitlines()]
        for cmd in (c.strip() for c in commands.splitlines()):
            if cmd.startswith("no ") and cmd not in lignes:  # IOS affiche les « no » dans la running-config
                self.config = self.config.replace("end\n", cmd + "\nend\n")
        return "ok"


@pytest.fixture
def faux_cisco(monkeypatch):
    from backend.app.modules.netdevops import service as nd
    dev = FauxCisco()
    monkeypatch.setattr(nd, "_fetch_live_config", dev.fetch)
    monkeypatch.setattr(nd, "_push_config_ios", dev.push)
    return dev


