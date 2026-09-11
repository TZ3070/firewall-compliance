import asyncio
import json

import httpx

from app.models.runtime import AgentRunStatus
from app.providers.agent_compose import AgentComposeClient
from app.services.conversation_agent import CONVERSATION_OUTPUT_SCHEMA


def test_agent_compose_connectrpc_contract() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/StartAgentRun"):
            return httpx.Response(
                200,
                json={
                    "run": {
                        "runId": "run-123",
                        "status": "RUN_STATUS_PENDING",
                    },
                    "started": True,
                },
            )
        return httpx.Response(
            200,
            json={
                "run": {
                    "summary": {
                        "runId": "run-123",
                        "status": "RUN_STATUS_SUCCEEDED",
                        "startedAt": "2026-09-02T00:00:00Z",
                        "completedAt": "2026-09-02T00:00:01Z",
                    },
                    "resultJson": json.dumps(
                        {
                            "assessmentId": "assessment-1",
                            "prepared": True,
                            "summary": "done",
                        }
                    ),
                }
            },
        )

    client = AgentComposeClient(
        base_url="http://agent-compose:7410",
        project_id="project-1",
        auth_token="secret",
        transport=httpx.MockTransport(handler),
    )
    started = asyncio.run(
        client.start_run(
            agent_name="firewall-compliance-agent",
            prompt="run",
            payload={"assessmentId": "assessment-1"},
            output_schema={"type": "object"},
            client_request_id="request-1",
        )
    )
    completed = asyncio.run(client.get_run("run-123"))

    assert started.started is True
    assert started.run.status is AgentRunStatus.QUEUED
    assert completed.status is AgentRunStatus.SUCCEEDED
    assert completed.result == {
        "assessmentId": "assessment-1",
        "prepared": True,
        "summary": "done",
    }
    assert requests[0].url.path == (
        "/agentcompose.v2.RunService/StartAgentRun"
    )
    assert requests[0].headers["authorization"] == "Bearer secret"
    body = json.loads(requests[0].content)
    assert body["run"]["projectId"] == "project-1"
    assert body["run"]["agentName"] == "firewall-compliance-agent"
    assert body["run"]["clientRequestId"] == "request-1"


def test_agent_compose_extracts_schema_result_from_output_tail() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "run": {
                    "summary": {
                        "runId": "run-real",
                        "status": "RUN_STATUS_SUCCEEDED",
                    },
                    "resultJson": json.dumps(
                        {"agent": "codex", "success": True, "exitCode": 0}
                    ),
                    "output": (
                        '$ curl tool\\n{"prepared":true}'
                        '{"assessmentId":"assessment-real",'
                        '"prepared":true,"summary":"done"}\n'
                    ),
                }
            },
        )

    client = AgentComposeClient(
        base_url="http://agent-compose:7410",
        project_id="project-1",
        transport=httpx.MockTransport(handler),
    )
    completed = asyncio.run(client.get_run("run-real"))

    assert completed.result == {
        "assessmentId": "assessment-real",
        "prepared": True,
        "summary": "done",
    }


def test_conversation_schema_supports_finding_filters_in_strict_mode() -> None:
    properties = CONVERSATION_OUTPUT_SCHEMA["properties"]

    assert set(CONVERSATION_OUTPUT_SCHEMA["required"]) == set(properties)
    assert properties["findingFilter"]["enum"] == [
        "Passed",
        "Failed",
        "NeedsReview",
        "NotApplicable",
        None,
    ]
