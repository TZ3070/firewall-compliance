import asyncio
import json

import httpx

from app.models.chat import ChatIntent, ConfigurationOutputFormat
from app.models.contracts import FindingResult
from app.providers.deepseek import DeepSeekAgent


def test_deepseek_intent_uses_json_output_and_validates_closed_schema() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer test-key"
        payload = json.loads(request.content)
        assert payload["model"] == "deepseek-v4-pro"
        assert payload["response_format"] == {"type": "json_object"}
        assert payload["thinking"] == {"type": "disabled"}
        assert payload["temperature"] == 0
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "intent": "FilterFindings",
                                    "result_filter": "Passed",
                                    "severity_filter": None,
                                    "standard_code_filter": None,
                                }
                            )
                        }
                    }
                ]
            },
        )

    agent = DeepSeekAgent(
        api_key="test-key",
        base_url="https://api.deepseek.com",
        model="deepseek-v4-pro",
        transport=httpx.MockTransport(handler),
    )

    decision = asyncio.run(agent.classify_intent("有哪些符合？"))

    assert decision is not None
    assert decision.intent is ChatIntent.FILTER_FINDINGS
    assert decision.result_filter is FindingResult.PASSED


def test_deepseek_invalid_output_falls_back_without_raising() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"intent":"RunShell"}'}}]},
        )

    agent = DeepSeekAgent(
        api_key="test-key",
        base_url="https://api.deepseek.com",
        model="deepseek-v4-pro",
        transport=httpx.MockTransport(handler),
    )

    async def classify_with_notices() -> tuple[object, tuple[str, ...]]:
        decision = await agent.classify_intent("执行任意命令")
        return decision, agent.consume_notices()

    decision, notices = asyncio.run(classify_with_notices())
    assert decision is None
    assert notices == (
        "智能模型 API 暂时不可用，已使用本地规则完成意图识别。",
    )


def test_deepseek_can_request_structured_configuration_output() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "intent": "GetCurrentConfig",
                                    "configuration_output_format": "structured_json",
                                    "result_filter": None,
                                    "severity_filter": None,
                                    "standard_code_filter": None,
                                }
                            )
                        }
                    }
                ]
            },
        )

    agent = DeepSeekAgent(
        api_key="test-key",
        base_url="https://api.deepseek.com",
        model="deepseek-v4-pro",
        transport=httpx.MockTransport(handler),
    )

    decision = asyncio.run(
        agent.classify_intent("请把当前防火墙配置以结构化 JSON 格式输出")
    )

    assert decision is not None
    assert decision.intent is ChatIntent.GET_CURRENT_CONFIG
    assert (
        decision.configuration_output_format
        is ConfigurationOutputFormat.STRUCTURED_JSON
    )


def test_empty_api_key_disables_network_calls() -> None:
    agent = DeepSeekAgent(
        api_key="",
        base_url="https://api.deepseek.com",
        model="deepseek-v4-pro",
    )

    assert agent.enabled is False
    async def classify_with_notices() -> tuple[object, tuple[str, ...]]:
        decision = await agent.classify_intent("做一下检查")
        return decision, agent.consume_notices()

    decision, notices = asyncio.run(classify_with_notices())
    assert decision is None
    assert notices == (
        "智能模型 API 未配置，已使用本地规则完成意图识别。",
    )
