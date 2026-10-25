"""Schémas Pydantic pour l'authentification et les profils utilisateurs."""
from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime


class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    nom_complet: str
    identifiant: str


class TokenData(BaseModel):
    identifiant: Optional[str] = None
    role: Optional[str] = None


class LoginRequest(BaseModel):
    identifiant: str
    mot_de_passe: str


class RegisterRequest(BaseModel):
    identifiant: str
    email: str
    nom_complet: str
    mot_de_passe: str
    role: str = "Technicien"


class UserOut(BaseModel):
    id: int
    identifiant: str
    email: str
    nom_complet: str
    role: str
    mfa_active: bool
    est_actif: bool
    date_creation: datetime
    derniere_connexion: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
