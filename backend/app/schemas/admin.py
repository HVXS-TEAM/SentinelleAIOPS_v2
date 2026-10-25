"""
Schémas Pydantic pour l'Administration, RBAC et Notifications Multi-Canaux.
"""

from __future__ import annotations

from typing import Literal, Optional, List
from pydantic import BaseModel, EmailStr, Field


class CreateUserRequest(BaseModel):
    identifiant: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    nom_complet: str = Field(..., min_length=2, max_length=100)
    mot_de_passe: str = Field(..., min_length=8)
    role: str = Field(default="Technicien", pattern="^(Administrateur|Technicien|Visiteur)$")


class TelegramChannelConfig(BaseModel):
    bot_token: str = Field(..., description="Token du bot Telegram fourni par @BotFather")
    chat_id: str = Field(..., description="Identifiant du salon ou @username du canal")


class DiscordChannelConfig(BaseModel):
    webhook_url: str = Field(..., description="URL complète du Webhook Discord")


class EmailChannelConfig(BaseModel):
    smtp_server: str = Field(default="smtp.sentinelle.local", description="Hôte du serveur SMTP")
    smtp_port: int = Field(default=587, ge=1, le=65535, description="Port d'écoute SMTP")
    recipient: str = Field(..., description="Adresse email du destinataire des alertes (ex: admin@sentinelle.local)")
    use_tls: bool = Field(default=True, description="Chiffrement STARTTLS")


class NotificationTestRequest(BaseModel):
    channel: Literal["telegram", "discord", "email"]
    message: Optional[str] = None
    telegram_config: Optional[TelegramChannelConfig] = None
    discord_config: Optional[DiscordChannelConfig] = None
    email_config: Optional[EmailChannelConfig] = None


class NotificationTestResponse(BaseModel):
    success: bool
    channel: str
    message: str
    details: Optional[str] = None


class NotificationDispatchRequest(BaseModel):
    channels: List[Literal["telegram", "discord", "email"]]
    titre: str
    message: str
    severite: Literal["INFO", "WARNING", "CRITICAL"] = "CRITICAL"
    telegram_config: Optional[TelegramChannelConfig] = None
    discord_config: Optional[DiscordChannelConfig] = None
    email_config: Optional[EmailChannelConfig] = None


class NotificationDispatchResponse(BaseModel):
    total_envoyes: int
    echecs: int
    rapports: List[NotificationTestResponse]
