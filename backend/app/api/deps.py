"""Dépendances FastAPI réutilisables (Session DB, Authentification JWT, RBAC)."""
from typing import List, Callable
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from backend.app.db.session import get_db
from backend.app.db.models import User
from backend.app.core.config import settings
from backend.app.schemas.auth import TokenData

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login-form")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Valide le jeton JWT et retourne l'utilisateur authentifié."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Identifiants d'accès invalides ou expirés",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        identifiant: str = payload.get("sub")
        role: str = payload.get("role")
        if identifiant is None:
            raise credentials_exception
        token_data = TokenData(identifiant=identifiant, role=role)
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.identifiant == token_data.identifiant).first()
    if user is None or not user.est_actif:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte utilisateur inactif ou introuvable",
        )
    return user


def require_roles(allowed_roles: List[str]) -> Callable:
    """Génère une dépendance vérifiant que l'utilisateur possède l'un des rôles requis (RBAC)."""
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Action non autorisée pour le rôle '{current_user.role}'. Rôles requis: {allowed_roles}",
            )
        return current_user
    return role_checker
