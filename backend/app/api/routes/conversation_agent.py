from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.routes.assessments import get_agent_compose_client
from app.core.config import get_settings
from app.models.runtime import (
    ConversationAgentRequest,
    ConversationRunResponse,
    ConversationRunView,
)
from app.providers.agent_compose import (
    AgentComposeProtocolError,
    AgentComposeUnavailableError,
)
from app.services.conversation_agent import ConversationAgentService


router = APIRouter(tags=["conversation-agent"])


@lru_cache
def get_conversation_agent_service() -> ConversationAgentService:
    return ConversationAgentService(
        runtime=get_agent_compose_client(),
        settings=get_settings(),
    )


@router.post(
    "/api/v1/conversations/messages",
    response_model=ConversationRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_conversation_message(
    request: ConversationAgentRequest,
    service: Annotated[
        ConversationAgentService,
        Depends(get_conversation_agent_service),
    ],
) -> ConversationRunResponse:
    try:
        return await service.start(request)
    except AgentComposeUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "AGENT_RUNTIME_UNAVAILABLE", "message": str(exc)},
        ) from exc
    except AgentComposeProtocolError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"code": "AGENT_RUNTIME_PROTOCOL_ERROR", "message": str(exc)},
        ) from exc


@router.get(
    "/api/v1/conversation-runs/{run_id}",
    response_model=ConversationRunView,
)
async def get_conversation_run(
    run_id: str,
    service: Annotated[
        ConversationAgentService,
        Depends(get_conversation_agent_service),
    ],
) -> ConversationRunView:
    try:
        return await service.get_run(run_id)
    except AgentComposeUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "AGENT_RUNTIME_UNAVAILABLE", "message": str(exc)},
        ) from exc
