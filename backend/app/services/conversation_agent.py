from uuid import uuid4

from app.core.config import Settings
from app.models.runtime import (
    ConversationAgentRequest,
    ConversationRunResponse,
    ConversationRunView,
)
from app.providers.agent_compose import AgentComposeClient


CONVERSATION_OUTPUT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    # DeepSeek strict structured output requires every declared property to
    # appear in required. Optional resource values are represented as null.
    "required": [
        "intent",
        "message",
        "resourceId",
        "resourceType",
        "findingFilter",
    ],
    "properties": {
        "intent": {
            "type": "string",
            "enum": [
                "RunAssessment",
                "GetRun",
                "GetLatestReport",
                "ListReports",
                "GetCurrentConfig",
                "SearchStandards",
                "Help",
                "Unsupported",
            ],
        },
        "message": {"type": "string"},
        "resourceId": {"type": ["string", "null"]},
        "resourceType": {
            "type": ["string", "null"],
            "enum": ["assessment-run", "report", "configuration", None],
        },
        "findingFilter": {
            "type": ["string", "null"],
            "enum": ["Passed", "Failed", "NeedsReview", "NotApplicable", None],
        },
    },
}


class ConversationAgentService:
    def __init__(self, *, runtime: AgentComposeClient, settings: Settings) -> None:
        self._runtime = runtime
        self._settings = settings

    async def start(
        self,
        request: ConversationAgentRequest,
    ) -> ConversationRunResponse:
        conversation_id = request.conversation_id or f"conversation-{uuid4().hex}"
        client_request_id = request.client_request_id or f"message-{uuid4().hex}"
        result = await self._runtime.start_run(
            agent_name=self._settings.agent_compose_conversation_agent,
            prompt=(
                f"conversationId={conversation_id}\n"
                f"用户消息：{request.message}\n"
                "先判断意图；涉及配置、报告、标准或检测时必须调用相应 API。"
                "如果用户只问合规、不合规、待复核或不适用条目，必须读取最新报告，"
                "并设置对应的 findingFilter。"
            ),
            payload={
                "conversationId": conversation_id,
                "message": request.message,
            },
            output_schema=CONVERSATION_OUTPUT_SCHEMA,
            client_request_id=client_request_id,
        )
        return ConversationRunResponse(
            conversation_id=conversation_id,
            run_id=result.run.run_id,
            status=result.run.status,
            started=result.started,
            status_url=f"/api/v1/conversation-runs/{result.run.run_id}",
        )

    async def get_run(self, run_id: str) -> ConversationRunView:
        run = await self._runtime.get_run(run_id)
        return ConversationRunView(
            run_id=run.run_id,
            status=run.status,
            response=run.result,
            error_message=run.error,
            started_at=run.started_at,
            completed_at=run.completed_at,
            warnings=run.warnings,
        )
