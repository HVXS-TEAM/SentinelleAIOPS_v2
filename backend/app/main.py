"""Sentinelle AIOps — Backend API Server (FastAPI)."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.api.v1.router import api_router
from backend.app.db.session import engine, Base

# Création automatique des tables au démarrage si absentes
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="API REST centralisée pour la supervision prédictive, la cybersécurité et l'automatisation NetDevOps (BTS SIO / SISR).",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configuration CORS pour le Frontend React (Vite)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    return {
        "status": "healthy",
        "database": "sqlite/postgresql_ready",
        "modules": {
            "securite": "ready",
            "supervision": "ready",
            "netdevops": "ready",
            "parc": "ready",
        }
    }
