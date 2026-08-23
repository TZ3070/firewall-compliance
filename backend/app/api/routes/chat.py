from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.routes.reports import get_knowledge_store, get_report_service
from app.core.config import get_settings
from app.models.chat import ChatRequest, ChatResponse
from app.providers.deepseek import DeepSeekAgent
from app.services.chat import ChatService
from app.services.configuration import ConfigurationService


router = APIRouter(prefix="/api/v1/chat", tags=["chat"])


@lru_cache
def get_chat_service() -> ChatService:
    settings = get_settings()
    return ChatService(
        report_service=get_report_service(),
        configuration_service=ConfigurationService(),
        knowledge_retriever=get_knowledge_store(),
        deepseek_agent=DeepSeekAgent(
            api_key=settings.deepseek_api_key,
            base_url=settings.deepseek_base_url,
            model=settings.deepseek_model,
            timeout_seconds=settings.deepseek_timeout_seconds,
        ),
    )


@router.post("/messages", response_model=ChatResponse)
async def post_chat_message(
    request: ChatRequest,
    service: Annotated[ChatService, Depends(get_chat_service)],
) -> ChatResponse:
    return await service.handle(request)
