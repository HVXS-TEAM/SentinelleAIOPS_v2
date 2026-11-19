"""Isolation des données : les tests ne doivent jamais toucher à la base de développement
ni aux fichiers suivis par git, et le dépôt ne doit plus versionner d'artefacts d'exécution.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.core import config as cfg
from backend.app.db.session import engine
from backend.app.main import app

ROOT = Path(__file__).resolve().parents[2]
client = TestClient(app)


def _est_sous(enfant: Path, parent: Path) -> bool:
    enfant, parent = enfant.resolve(), parent.resolve()
    return enfant == parent or parent in enfant.parents


# ── Les données de test vivent dans un dossier temporaire ────────────────────

def test_les_donnees_de_test_sont_hors_du_depot():
    dossier_test = Path(os.environ["SENTINELLE_DATA_DIR"])
    assert not _est_sous(dossier_test, ROOT)
    for chemin in (cfg.DATA_DIR, cfg.BACKUP_DIR, cfg.CONFIG_BACKUP_DIR, cfg.DB_FILE_PATH, cfg.SECRETS_FILE):
        assert _est_sous(Path(chemin), dossier_test), f"{chemin} n'est pas dans le dossier de test"
        assert not _est_sous(Path(chemin), ROOT), f"{chemin} est dans le dépôt"


def test_la_base_de_test_n_est_pas_la_base_de_developpement():
    base_utilisee = Path(engine.url.database).resolve()
    assert _est_sous(base_utilisee, Path(os.environ["SENTINELLE_DATA_DIR"]))
    assert base_utilisee != (ROOT / "backend" / "sentinelle.db").resolve()


def test_sauvegarde_pra_ecrit_dans_le_dossier_temporaire(admin_headers):
    """Une sauvegarde PRA réelle ne doit laisser aucune trace dans le dépôt."""
    dossier_depot = ROOT / "backup"
    avant = sorted(p.name for p in dossier_depot.glob("*")) if dossier_depot.exists() else []
    resp = client.post("/api/v1/admin/pra/backup", headers=admin_headers)
    assert resp.status_code == 200, resp.text
    apres = sorted(p.name for p in dossier_depot.glob("*")) if dossier_depot.exists() else []
    assert apres == avant, "une sauvegarde de test a été écrite dans le dépôt"
    assert any(cfg.BACKUP_DIR.glob("*.db")), "la sauvegarde devrait être dans le dossier temporaire"


# ── SENTINELLE_DATA_DIR ──────────────────────────────────────────────────────

def test_variable_data_dir_redirige_toutes_les_donnees(monkeypatch, tmp_path):
    cible = tmp_path / "donnees_sentinelle"
    monkeypatch.setenv("SENTINELLE_DATA_DIR", str(cible))
    base_dir, bundle_dir, data_dir, db_file = cfg._resolve_directories()
    assert data_dir == cible.resolve()
    assert db_file == cible.resolve() / "sentinelle.db"
    assert cible.is_dir()  # créé automatiquement


def test_sans_variable_les_chemins_par_defaut_sont_inchanges(monkeypatch):
    monkeypatch.delenv("SENTINELLE_DATA_DIR", raising=False)
    if getattr(sys, "frozen", False):
        pytest.skip("mode compilé : chemins dépendants de l'exécutable")
    base_dir, bundle_dir, data_dir, db_file = cfg._resolve_directories()
    assert base_dir == ROOT / "backend"
    assert data_dir == ROOT
    assert db_file == ROOT / "backend" / "sentinelle.db"


# ── Le dépôt ne versionne plus d'artefacts d'exécution ───────────────────────

PATTERNS_GITIGNORE = [
    "/backup/",
    "/notification_settings.json",
    "/ssh_known_hosts",
    "/logs/",
    "backend/data/",
    "*.db-wal",
    "*.db-shm",
    ".sentinelle_secrets.json",
    ".env",
]


@pytest.mark.parametrize("motif", PATTERNS_GITIGNORE)
def test_gitignore_contient_les_artefacts_d_execution(motif):
    lignes = {l.strip() for l in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()}
    assert motif in lignes, f"{motif} absent du .gitignore"


def test_aucun_artefact_d_execution_n_est_suivi_par_git():
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("git indisponible ou dépôt non initialisé")
    suivis = subprocess.run(
        ["git", "ls-files", "--", "backup", "backend/data", "notification_settings.json",
         "backend/sentinelle.db", "backend/sentinelle.db-wal", "backend/sentinelle.db-shm"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()
    assert not suivis, f"Artefacts d'exécution encore suivis par git : {suivis[:5]}"

