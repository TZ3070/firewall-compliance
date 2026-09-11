from __future__ import annotations

import hmac
from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import Field

from app.api.dependencies import get_knowledge_store
from app.core.config import get_settings
from app.models.contracts import FrozenConfigModel
from app.repositories.sqlite_assessment_session import (
    SQLiteAssessmentSessionRepository,
)
from app.rules.p0 import P0CurrentConfigRuleEngine
from app.services.agent_tools import (
    AgentToolSequenceError,
    ComplianceAgentToolService,
)
from app.services.configuration import ConfigurationService


router = APIRouter(prefix="/api/v1/agent-tools", tags=["agent-tools"])


class AgentToolRequest(FrozenConfigModel):
    assessment_id: str = Field(min_length=1, max_length=256)


class StandardsSearchToolRequest(AgentToolRequest):
    query: str = Field(min_length=2, max_length=1000)


def verify_agent_tool_token(
    x_agent_tool_token: Annotated[str | None, Header()] = None,
) -> None:
    expected = get_settings().agent_tool_token
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "AGENT_TOOL_TOKEN_NOT_CONFIGURED",
                "message": "Agent 工具网关未配置共享令牌",
            },
        )
    if not hmac.compare_digest(x_agent_tool_token or "", expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AGENT_TOOL_UNAUTHORIZED", "message": "Agent 工具令牌无效"},
        )


@lru_cache
def get_assessment_sessions() -> SQLiteAssessmentSessionRepository:
    return SQLiteAssessmentSessionRepository(get_settings().resolved_database_path)


@lru_cache
def get_agent_tool_service() -> ComplianceAgentToolService:
    return ComplianceAgentToolService(
        configuration_service=ConfigurationService(),
        rule_engine=P0CurrentConfigRuleEngine(),
        knowledge_retriever=get_knowledge_store(),
        sessions=get_assessment_sessions(),
    )


async def _call(operation):
    try:
        return await operation
    except AgentToolSequenceError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "AGENT_TOOL_SEQUENCE_INVALID", "message": str(exc)},
        ) from exc


@router.post("/configuration/fetch", dependencies=[Depends(verify_agent_tool_token)])
async def fetch_configuration(
    request: AgentToolRequest,
    service: Annotated[ComplianceAgentToolService, Depends(get_agent_tool_service)],
):
    return await _call(service.fetch_configuration(request.assessment_id))


@router.post("/vendor/detect", dependencies=[Depends(verify_agent_tool_token)])
async def detect_vendor(
    request: AgentToolRequest,
    service: Annotated[ComplianceAgentToolService, Depends(get_agent_tool_service)],
):
    return await _call(service.detect_vendor(request.assessment_id))


@router.post("/configuration/parse", dependencies=[Depends(verify_agent_tool_token)])
async def parse_configuration(
    request: AgentToolRequest,
    service: Annotated[ComplianceAgentToolService, Depends(get_agent_tool_service)],
):
    return await _call(service.parse_configuration(request.assessment_id))


@router.post("/rules/evaluate", dependencies=[Depends(verify_agent_tool_token)])
async def evaluate_rules(
    request: AgentToolRequest,
    service: Annotated[ComplianceAgentToolService, Depends(get_agent_tool_service)],
):
    return await _call(service.evaluate_rules(request.assessment_id))


@router.post("/standards/search", dependencies=[Depends(verify_agent_tool_token)])
async def search_standards(
    request: StandardsSearchToolRequest,
    service: Annotated[ComplianceAgentToolService, Depends(get_agent_tool_service)],
):
    return await _call(
        service.search_standards(request.assessment_id, request.query)
    )


@router.post("/report/prepare", dependencies=[Depends(verify_agent_tool_token)])
async def prepare_report(
    request: AgentToolRequest,
    service: Annotated[ComplianceAgentToolService, Depends(get_agent_tool_service)],
):
    return await _call(service.prepare_report(request.assessment_id))
