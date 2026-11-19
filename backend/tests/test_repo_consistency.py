"""Garde-fous de cohérence du dépôt : dépendances, configuration et README.

Empêche le retour des dérives constatées lors de la revue :
  - un import tiers absent de requirements.txt (le backend planterait sur une installation propre) ;
  - une dépendance listée mais jamais utilisée ;
  - un lien ou une ancre du README qui ne mène nulle part ;
  - un .env.example qui documente des variables inexistantes.
"""
import ast
import re
import sys
import unicodedata
from pathlib import Path

import pytest

from backend.app.core.config import Settings

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"

# Nom du module importé -> nom du paquet pip
IMPORT_TO_DIST = {
    "jose": "python-jose",
    "yaml": "pyyaml",
    "sklearn": "scikit-learn",
    "pydantic_settings": "pydantic-settings",
    "PyQt6": "pyqt6",
}
# Paquets nécessaires à l'exécution sans être importés directement
INDIRECT = {
    "uvicorn": "lancé par le lanceur (importé), mais l'extra [standard] apporte websockets/uvloop",
    "python-multipart": "requis par FastAPI pour OAuth2PasswordRequestForm",
}


def _parse_requirements(path: Path) -> set[str]:
    names: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name = re.split(r"[\[<>=!~; ]", line, maxsplit=1)[0]
        names.add(name.lower().replace("_", "-"))
    return names


def _third_party_imports(paths: list[Path]) -> set[str]:
    stdlib = set(sys.stdlib_module_names)
    found: set[str] = set()
    for p in paths:
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module]
            for m in mods:
                root = m.split(".")[0]
                if root not in stdlib and root != "backend":
                    found.add(root)
    return found


def _py_files(*roots: str) -> list[Path]:
    files: list[Path] = []
    for r in roots:
        base = ROOT / r
        files += [base] if base.is_file() else sorted(base.rglob("*.py"))
    return [f for f in files if "__pycache__" not in f.parts]


# ── Dépendances ──────────────────────────────────────────────────────────────

def test_requirements_est_a_la_racine():
    assert (ROOT / "requirements.txt").exists()
    assert not (ROOT / "backend" / "requirements.txt").exists()


def test_tout_import_du_backend_est_declare():
    declared = _parse_requirements(ROOT / "requirements.txt")
    imports = _third_party_imports(_py_files("backend/app"))
    manquants = sorted(
        dist
        for dist in (IMPORT_TO_DIST.get(m, m).lower().replace("_", "-") for m in imports)
        if dist not in declared
    )
    assert not manquants, f"Importés mais absents de requirements.txt : {manquants}"


def test_aucune_dependance_inutile_dans_requirements():
    declared = _parse_requirements(ROOT / "requirements.txt")
    imports = {
        IMPORT_TO_DIST.get(m, m).lower().replace("_", "-")
        for m in _third_party_imports(_py_files("backend/app"))
    }
    inutiles = sorted(declared - imports - set(INDIRECT))
    assert not inutiles, f"Listées mais jamais importées : {inutiles}"


def test_python_multipart_declare():
    assert "python-multipart" in _parse_requirements(ROOT / "requirements.txt")


def test_lanceur_et_tests_ont_leurs_dependances():
    desktop = _parse_requirements(ROOT / "requirements-desktop.txt")
    dev = _parse_requirements(ROOT / "requirements-dev.txt")
    assert "pyqt6" in desktop and "pyinstaller" in desktop
    assert "pytest" in dev
    launcher_imports = _third_party_imports(_py_files("launcher.py"))
    for m in launcher_imports:
        dist = IMPORT_TO_DIST.get(m, m).lower().replace("_", "-")
        assert dist in desktop | _parse_requirements(ROOT / "requirements.txt"), dist


# ── .env.example ─────────────────────────────────────────────────────────────

def test_env_example_ne_documente_que_des_variables_reelles():
    texte = (ROOT / "backend" / ".env.example").read_text(encoding="utf-8")
    cles = set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]+)=", texte, flags=re.MULTILINE))
    assert {"SECRET_KEY", "FERNET_KEY", "CORS_ORIGINS", "ALLOW_SELF_REGISTRATION"} <= cles
    inconnues = sorted(c for c in cles if c not in Settings.model_fields)
    assert not inconnues, f".env.example cite des variables inconnues : {inconnues}"


def test_cors_origins_lu_depuis_l_environnement(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", '["https://soc.exemple.fr"]')
    assert Settings().CORS_ORIGINS == ["https://soc.exemple.fr"]


# ── README ───────────────────────────────────────────────────────────────────

def _github_slug(titre: str) -> str:
    t = unicodedata.normalize("NFC", titre.strip().lower())
    t = re.sub(r"[^\w\- ]", "", t, flags=re.UNICODE)
    return t.replace(" ", "-")


def _readme_text_sans_code() -> str:
    return re.sub(r"```.*?```", "", README.read_text(encoding="utf-8"), flags=re.DOTALL)


def test_liens_relatifs_du_readme_existent():
    texte = README.read_text(encoding="utf-8")
    liens = re.findall(r"\]\(([^)\s]+)\)", texte) + re.findall(r'src="([^"]+)"', texte)
    cassés = []
    for lien in liens:
        if lien.startswith(("http://", "https://", "#", "mailto:")):
            continue
        if not (ROOT / lien.split("#")[0]).exists():
            cassés.append(lien)
    assert not cassés, f"Liens du README vers des fichiers absents : {cassés}"


def test_ancres_du_readme_pointent_vers_un_titre():
    texte = _readme_text_sans_code()
    slugs = {_github_slug(m.group(1)) for m in re.finditer(r"^#{1,6}\s+(.+?)\s*$", texte, flags=re.MULTILINE)}
    cassées = [a for a in re.findall(r"\]\(#([^)]+)\)", texte) if a not in slugs]
    assert not cassées, f"Ancres sans titre correspondant : {cassées}"


@pytest.mark.parametrize(
    "affirmation_fausse",
    [
        "backend/rules/",       # le dossier réel est backend/config/
        "Netmiko",              # non utilisé : SSH via Paramiko
        "Holt",                 # lissage de Holt non implémenté
        "NetBIOS",              # non implémenté (DNS inverse uniquement)
        "PRAGMA integrity_check",
        "60 tests",
        "en cours d'intégration",  # le MFA TOTP est désormais réellement exigé à la connexion
    ],
)
def test_readme_ne_contient_plus_d_affirmation_fausse(affirmation_fausse):
    assert affirmation_fausse not in README.read_text(encoding="utf-8")


def test_chemins_cites_dans_le_readme_existent():
    texte = README.read_text(encoding="utf-8")
    for chemin in [
        "backend/config/cis_rules.yaml",
        "backend/app/db/init_db.py",
        "backend/.env.example",
        ".github/workflows/ci.yml",
        "launcher.py",
        "sentinelle.spec",
        "installer.nsi",
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-desktop.txt",
    ]:
        assert chemin in texte, f"{chemin} n'est plus cité dans le README"
        assert (ROOT / chemin).exists(), f"{chemin} cité mais absent du dépôt"

