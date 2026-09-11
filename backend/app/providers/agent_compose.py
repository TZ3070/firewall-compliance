from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import httpx

from app.models.runtime import (
    AgentComposeRun,
    AgentComposeStartResult,
    AgentRunStatus,
)


class AgentComposeUnavailableError(RuntimeError):
    pass


class AgentComposeProtocolError(RuntimeError):
    pass


_STATUS_MAP = {
    "RUN_STATUS_PENDING": AgentRunStatus.QUEUED,
    "RUN_STATUS_RUNNING": AgentRunStatus.RUNNING,
    "RUN_STATUS_SUCCEEDED": AgentRunStatus.SUCCEEDED,
    "RUN_STATUS_FAILED": AgentRunStatus.FAILED,
    "RUN_STATUS_CANCELED": AgentRunStatus.CANCELED,
    1: AgentRunStatus.QUEUED,
    2: AgentRunStatus.RUNNING,
    3: AgentRunStatus.SUCCEEDED,
    4: AgentRunStatus.FAILED,
    5: AgentRunStatus.CANCELED,
}


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _last_json_object(value: object) -> dict[str, object] | None:
    """Return a JSON object only when it is the final non-whitespace output."""

    if not isinstance(value, str) or not value:
        return None
    decoder = json.JSONDecoder()
    offset = value.rfind("{")
    while offset >= 0:
        try:
            decoded, end = decoder.raw_decode(value, offset)
        except json.JSONDecodeError:
            offset = value.rfind("{", 0, offset)
            continue
        if not value[end:].strip() and isinstance(decoded, dict):
            return decoded
        offset = value.rfind("{", 0, offset)
    return None


class AgentComposeClient:
    """Minimal ConnectRPC client for the Agent-Compose v2 RunService."""

    def __init__(
        self,
        *,
        base_url: str,
        project_id: str,
        auth_token: str = "",
        timeout_seconds: float = 15.0,
        enabled: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._project_id = project_id
        self._auth_token = auth_token
        self._timeout_seconds = timeout_seconds
        self._enabled = enabled
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
        }
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        return headers

    async def _post(self, procedure: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self._enabled:
            raise AgentComposeUnavailableError("Agent-Compose 已被配置为禁用")
        if not self._project_id:
            raise AgentComposeUnavailableError(
                "缺少 AGENT_COMPOSE_PROJECT_ID；请先执行 agent-compose up"
            )
        url = f"{self._base_url}/agentcompose.v2.RunService/{procedure}"
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout_seconds,
                transport=self._transport,
                # The control plane is an internal endpoint. In particular on
                # macOS, httpx may inherit the OS proxy even when proxy env
                # variables are absent, routing localhost traffic externally.
                trust_env=False,
            ) as client:
                response = await client.post(url, headers=self._headers(), json=payload)
                response.raise_for_status()
                body = response.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise AgentComposeUnavailableError(
                f"Agent-Compose RunService 不可用：{exc}"
            ) from exc
        if not isinstance(body, dict):
            raise AgentComposeProtocolError("Agent-Compose 返回了无效响应")
        return body

    @staticmethod
    def _parse_run(payload: dict[str, Any]) -> AgentComposeRun:
        summary = payload.get("summary", payload)
        if not isinstance(summary, dict):
            raise AgentComposeProtocolError("Agent-Compose 响应缺少 run summary")
        run_id = summary.get("runId") or summary.get("run_id")
        status_value = summary.get("status")
        if not isinstance(run_id, str) or status_value not in _STATUS_MAP:
            raise AgentComposeProtocolError("Agent-Compose run 标识或状态无效")
        # Agent-Compose stores runner metadata in resultJson. With the Codex
        # runner, the schema-constrained business result is the final JSON
        # object in output, after the tool transcript.
        result = _last_json_object(payload.get("output"))
        result_value = payload.get("resultJson") or payload.get("result_json")
        if result is None and isinstance(result_value, str) and result_value:
            try:
                decoded = json.loads(result_value)
                result = decoded if isinstance(decoded, dict) else {"value": decoded}
            except json.JSONDecodeError as exc:
                raise AgentComposeProtocolError("Agent 结构化输出不是有效 JSON") from exc
        return AgentComposeRun(
            run_id=run_id,
            status=_STATUS_MAP[status_value],
            started_at=_timestamp(summary.get("startedAt") or summary.get("started_at")),
            completed_at=_timestamp(
                summary.get("completedAt") or summary.get("completed_at")
            ),
            result=result,
            error=summary.get("error") if isinstance(summary.get("error"), str) else None,
            warnings=tuple(
                item for item in payload.get("warnings", ()) if isinstance(item, str)
            ),
        )

    async def start_run(
        self,
        *,
        agent_name: str,
        prompt: str,
        payload: dict[str, object],
        output_schema: dict[str, object],
        client_request_id: str,
    ) -> AgentComposeStartResult:
        body = await self._post(
            "StartAgentRun",
            {
                "run": {
                    "projectId": self._project_id,
                    "agentName": agent_name,
                    "prompt": prompt,
                    "source": "RUN_SOURCE_API",
                    "cleanupPolicy": "RUN_SANDBOX_CLEANUP_POLICY_STOP_ON_COMPLETION",
                    "outputSchemaJson": json.dumps(output_schema, ensure_ascii=False),
                    "clientRequestId": client_request_id,
                    "payloadJson": json.dumps(payload, ensure_ascii=False),
                }
            },
        )
        run_payload = body.get("run")
        if not isinstance(run_payload, dict):
            raise AgentComposeProtocolError("StartAgentRun 响应缺少 run")
        return AgentComposeStartResult(
            run=self._parse_run(run_payload),
            started=bool(body.get("started", False)),
        )

    async def get_run(self, run_id: str) -> AgentComposeRun:
        body = await self._post(
            "GetRun",
            {"runId": run_id, "projectId": self._project_id},
        )
        run_payload = body.get("run")
        if not isinstance(run_payload, dict):
            raise AgentComposeProtocolError("GetRun 响应缺少 run")
        return self._parse_run(run_payload)
