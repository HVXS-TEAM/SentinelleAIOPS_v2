"""Agrégation des routeurs de l'API v1."""
from fastapi import APIRouter
from backend.app.api.v1.endpoints import auth, supervision, parc, securite, netdevops, dashboard, assistant, admin

api_router = APIRouter(prefix="/api/v1")

# Routeurs métiers
api_router.include_router(auth.router)
api_router.include_router(supervision.router)
api_router.include_router(parc.router)
api_router.include_router(securite.router)
api_router.include_router(netdevops.router)
api_router.include_router(dashboard.router)
api_router.include_router(assistant.router)
api_router.include_router(admin.router)
