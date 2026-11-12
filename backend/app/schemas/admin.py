"""
Schémas Pydantic pour l'Administration, RBAC et Notifications Multi-Canaux.
"""

from __future__ import annotations

from typing import Literal, Optional, List
from pydantic import BaseModel, Field


class CreateUserRequest(BaseModel):
    identifiant: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
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


class NotificationSettingsPayload(BaseModel):
    """Configuration persistante des canaux de notification sur le serveur."""

    demo_mode: bool = Field(default=False, description="Mode simulation désactivé par défaut (envoi réel)")
    telegram_enabled: bool = Field(default=False)
    telegram_token: str = Field(default="")
    telegram_chat_id: str = Field(default="")
    discord_enabled: bool = Field(default=False)
    discord_webhook: str = Field(default="")
    email_enabled: bool = Field(default=True)
    smtp_server: str = Field(default="smtp.gmail.com")
    smtp_port: int = Field(default=587, ge=1, le=65535)
    email_recipient: str = Field(default="admin@sentinelle.local")
    email_use_tls: bool = Field(default=True)


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
