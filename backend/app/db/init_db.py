"""Initialisation de la base de données (production uniquement).

Aucune donnée n'est injectée : ni compte, ni équipement, ni métrique, ni alerte. Le premier
administrateur est créé par l'assistant de première configuration (POST /auth/setup) et le parc
est alimenté par la supervision réelle (hôte local, découverte réseau, équipements saisis).
"""
from sqlalchemy.orm import Session

from backend.app.db.session import engine, SessionLocal, Base
from backend.app.db import models  # noqa: F401 - Charge les modèles dans Base.metadata


def init_db(db: Session) -> None:
    """Crée les tables manquantes. N'écrit aucune donnée métier."""
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    with SessionLocal() as _db:
        init_db(_db)
        print("Schéma de la base de données Sentinelle AIOps initialisé (aucune donnée injectée).")
