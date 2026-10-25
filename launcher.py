"""
Lanceur autonome Sentinelle AIOps.
Ce script est le point d'entrée pour le packaging PyInstaller (.exe).
Il initialise la base de données, monte le build statique React (SPA),
démarre le serveur FastAPI (Uvicorn) et ouvre automatiquement le navigateur.
"""

from __future__ import annotations

import os
import sys
import time
import threading
import webbrowser
from pathlib import Path

# Ajouter le répertoire racine au PYTHONPATH
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys._MEIPASS)
    APP_DIR = Path(os.path.dirname(sys.executable))
else:
    BASE_DIR = Path(__file__).resolve().parent
    APP_DIR = BASE_DIR

sys.path.insert(0, str(BASE_DIR))

import uvicorn
from fastapi import Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.app.main import app
from backend.app.db.session import engine, SessionLocal, Base
from backend.app.db.init_db import init_db


def setup_database() -> None:
    """Initialise les tables et injecte les données par défaut si nécessaire."""
    print(" [1/3] Initialisation de la base de données SQLite...")
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        init_db(db)
    print("       Base de données SQLite opérationnelle.")


def setup_static_routes() -> None:
    """Monte l'interface web React/Vite sur FastAPI."""
    dist_dir = BASE_DIR / "frontend" / "dist"
    print(f" [2/3] Montage des assets frontend depuis : {dist_dir}")

    if dist_dir.exists():
        assets_dir = dist_dir / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @app.middleware("http")
        async def spa_root_redirect(request: Request, call_next):
            # Si un navigateur consulte la racine '/', renvoyer l'application SPA
            if request.url.path == "/" and "text/html" in request.headers.get("accept", ""):
                index_path = dist_dir / "index.html"
                if index_path.exists():
                    return FileResponse(str(index_path))
            return await call_next(request)

        # Fallback pour le routage Single Page Application (SPA)
        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(request: Request, full_path: str):
            # Ne pas intercepter les routes API, docs ou favicon si non trouvées
            if full_path.startswith("api/") or full_path.startswith("docs") or full_path.startswith("redoc"):
                return FileResponse(dist_dir / "index.html")

            candidate = dist_dir / full_path
            if candidate.exists() and candidate.is_file():
                return FileResponse(str(candidate))
            return FileResponse(str(dist_dir / "index.html"))

        print("       Routage SPA et fichiers statiques configurés avec succès.")
    else:
        print(" [!] Avertissement : Répertoire 'frontend/dist' introuvable.")


def open_browser(url: str, delay: float = 1.5) -> None:
    """Ouvre le navigateur par défaut après le démarrage du serveur."""
    def _open():
        time.sleep(delay)
        print(f" [*] Ouverture de l'interface dans votre navigateur : {url}")
        webbrowser.open(url)

    thread = threading.Thread(target=_open, daemon=True)
    thread.start()


def main() -> None:
    """Point d'entrée principal de l'exécutable."""
    print("=" * 70)
    print("   SENTINELLE AIOPS — PLATEFORME DE SUPERVISION & RÉSILIENCE")
    print("   Projet BTS SIO SISR — Version Autonome .EXE (100% Réelle)")
    print("=" * 70)

    # 1. Base de données
    setup_database()

    # 2. Montage SPA
    setup_static_routes()

    # 3. Ouverture navigateur
    host = "127.0.0.1"
    port = 8000
    app_url = f"http://{host}:{port}"
    open_browser(app_url, delay=1.5)

    print(f" [3/3] Démarrage du serveur Uvicorn sur {app_url}...")
    print("       (Fermez cette fenêtre console pour arrêter l'application)")
    print("-" * 70)

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=False,
    )


if __name__ == "__main__":
    main()
