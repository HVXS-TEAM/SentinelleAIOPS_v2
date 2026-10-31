"""Gestionnaire de session de base de données SQLAlchemy."""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base
from typing import Generator
from backend.app.core.config import settings

# Arguments spécifiques pour SQLite (accès multi-threads concurrents sans blocage)
is_sqlite = "sqlite" in settings.DATABASE_URL
connect_args = {"check_same_thread": False, "timeout": 15} if is_sqlite else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

if is_sqlite:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record) -> None:
        """Active le mode WAL, les clés étrangères et un délai d'attente sur SQLite."""
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA busy_timeout=5000;")
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.close()
        except Exception:
            pass

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator:
    """Fournit une session de base de données avec fermeture automatique."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
