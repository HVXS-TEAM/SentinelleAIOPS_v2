"""Gestionnaire de session de base de données SQLAlchemy."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from typing import Generator
from backend.app.core.config import settings

# Arguments spécifiques pour SQLite
connect_args = {"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator:
    """Fournit une session de base de données avec fermeture automatique."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
