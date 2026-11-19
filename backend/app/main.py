"""Sentinelle AIOps — Backend API Server (FastAPI)."""
import platform
import subprocess
import uuid
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from backend.app.core.config import settings
from backend.app.core.logging_config import setup_logging
from backend.app.core.scheduler import start_background_scheduler
from backend.app.api.v1.router import api_router
from backend.app.db.session import engine, SessionLocal, Base
from backend.app.db.init_db import init_db
from backend.app.modules.supervision.hardware_collector import HardwareCollector

import logging
setup_logging()
logger = logging.getLogger("sentinelle.main")

# Protection globale Windows : empêcher toute ouverture de fenêtre console (conhost/cmd)
# par les sous-processus système ou bibliothèques tierces (joblib, sklearn, psutil, ping, arp)
if platform.system() == "Windows" and not getattr(subprocess.Popen, "_sentinelle_no_window_patched", False):
    _orig_popen_init = subprocess.Popen.__init__
    _CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    def _silent_popen_init(self, *args, **kwargs):
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | _CREATE_NO_WINDOW
        _orig_popen_init(self, *args, **kwargs)

    subprocess.Popen.__init__ = _silent_popen_init  # type: ignore[method-assign]
    subprocess.Popen._sentinelle_no_window_patched = True  # type: ignore[attr-defined]

# Création automatique des tables et collecte initiale de l'hôte réel au démarrage (aucune donnée fictive)
Base.metadata.create_all(bind=engine)
try:
    with SessionLocal() as _startup_db:
        init_db(_startup_db)
        HardwareCollector.collect_live_metrics(_startup_db)
except Exception as exc:
    logger.exception("Initialisation au démarrage en échec (base ou collecte initiale)")

# Démarrage de l'ordonnanceur de collecte continue en arrière-plan
start_background_scheduler()

# Récepteur syslog des équipements réseau (SYSLOG_ENABLED=true)
from backend.app.modules.securite.syslog_receiver import start_syslog_receiver  # noqa: E402
start_syslog_receiver()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="API REST centralisée pour la supervision prédictive, la cybersécurité et l'automatisation NetDevOps.",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configuration CORS : uniquement les origines déclarées (Vite en développement)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Erreur non prévue : trace complète dans les logs, réponse générique (aucun détail interne exposé)."""
    request_id = uuid.uuid4().hex[:12]
    logger.error(
        "Erreur non gérée [%s] %s %s", request_id, request.method, request.url.path,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Erreur interne du serveur", "request_id": request_id},
    )


# Branchement des routes API v1
app.include_router(api_router)


@app.get("/", tags=["Root"])
def root_status():
    return {
        "service": settings.PROJECT_NAME,
        "status": "online",
        "version": settings.VERSION,
        "docs": "/docs",
    }


@app.get("/api/v1/health", tags=["Health"])
def health_check():
    """Sonde de santé publique (sans authentification) : vérifie réellement la base de données."""
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as exc:
        logger.error("Sonde de santé : base de données inaccessible : %s", exc)
        db_status = "unavailable"

    payload = {
        "status": "healthy" if db_status == "ok" else "degraded",
        "database": db_status,
        "modules": {
            "securite": "ready",
            "supervision": "ready",
            "netdevops": "ready",
            "parc": "ready",
        },
    }
    return JSONResponse(status_code=200 if db_status == "ok" else 503, content=payload)
