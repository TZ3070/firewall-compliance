from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from time import monotonic

from app.models.chat import ChatIntent, ChatResponse


class QueryObject(StrEnum):
    CURRENT_CONFIG = "current_config"
    CURRENT_REPORT = "current_report"
    REPORT_LIST = "report_list"
    FINDINGS = "findings"
    FINDING = "finding"
    STANDARDS = "standards"


@dataclass(frozen=True)
class ConversationContext:
    previous_user_message: str
    previous_intent: ChatIntent
    last_query_object: QueryObject | None
    active_report_id: str | None
    updated_at: float


class ConversationContextStore:
    """Bounded, expiring P0 context; never stores tool payloads or model output."""

    def __init__(
        self,
        *,
        ttl_seconds: float = 1800.0,
        max_conversations: int = 1000,
    ) -> None:
        if ttl_seconds <= 0 or max_conversations <= 0:
            raise ValueError("context limits must be positive")
        self._ttl_seconds = ttl_seconds
        self._max_conversations = max_conversations
        self._contexts: OrderedDict[str, ConversationContext] = OrderedDict()
        self._lock = Lock()

    def get(self, conversation_id: str | None) -> ConversationContext | None:
        if not conversation_id:
            return None
        now = monotonic()
        with self._lock:
            self._evict_expired(now)
            context = self._contexts.get(conversation_id)
            if context is not None:
                self._contexts.move_to_end(conversation_id)
            return context

    def record(
        self,
        *,
        conversation_id: str,
        user_message: str,
        response: ChatResponse,
    ) -> None:
        now = monotonic()
        with self._lock:
            self._evict_expired(now)
            previous = self._contexts.get(conversation_id)
            query_object = self._query_object(response.intent)
            context = ConversationContext(
                previous_user_message=user_message,
                previous_intent=response.intent,
                last_query_object=(
                    query_object
                    if query_object is not None
                    else (previous.last_query_object if previous else None)
                ),
                active_report_id=(
                    response.active_report_id
                    or (previous.active_report_id if previous else None)
                ),
                updated_at=now,
            )
            self._contexts[conversation_id] = context
            self._contexts.move_to_end(conversation_id)
            while len(self._contexts) > self._max_conversations:
                self._contexts.popitem(last=False)

    def _evict_expired(self, now: float) -> None:
        expired = [
            conversation_id
            for conversation_id, context in self._contexts.items()
            if now - context.updated_at > self._ttl_seconds
        ]
        for conversation_id in expired:
            self._contexts.pop(conversation_id, None)

    @staticmethod
    def _query_object(intent: ChatIntent) -> QueryObject | None:
        return {
            ChatIntent.GET_CURRENT_CONFIG: QueryObject.CURRENT_CONFIG,
            ChatIntent.RUN_ASSESSMENT: QueryObject.CURRENT_REPORT,
            ChatIntent.LIST_REPORTS: QueryObject.REPORT_LIST,
            ChatIntent.FILTER_FINDINGS: QueryObject.FINDINGS,
            ChatIntent.EXPLAIN_FINDING: QueryObject.FINDING,
            ChatIntent.SEARCH_STANDARDS: QueryObject.STANDARDS,
        }.get(intent)
