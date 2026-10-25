"""
Endpoints REST – Module Assistant IA Conversationnel (Bloc 7).

Routes :
  POST /assistant/chat             → Envoi d'un message et réception de la réponse IA (RAG)
  GET  /assistant/suggested-prompts → Liste des questions suggérées
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.modules.assistant.service import AssistantService

router = APIRouter(prefix="/assistant", tags=["Assistant IA"])


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1000, description="Message ou question en langage naturel")


class ChatResponse(BaseModel):
    response: str
    sources: list[str]
    suggested_followups: list[str]
    mode: str


@router.post("/chat", response_model=ChatResponse, summary="Dialogue avec l'Assistant IA AIOps")
async def chat_with_assistant(
    request: ChatRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Traite la question de l'administrateur en langage naturel en exploitant :
    1. Le contexte opérationnel en temps réel extrait de la base SQLite (RAG)
    2. Le moteur LLM local Ollama (Llama 3 / Mistral) ou son fallback déterministe
    """
    return await AssistantService.chat(request.message, db)


@router.get("/suggested-prompts", response_model=list[str], summary="Questions suggérées pour la démo BTS")
def get_suggested_prompts() -> list[str]:
    """Retourne des requêtes types prêtes à l'emploi couvrant l'ensemble des modules."""
    return AssistantService.get_suggested_prompts()
