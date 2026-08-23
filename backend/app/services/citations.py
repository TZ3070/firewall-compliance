from __future__ import annotations

import logging

from app.models.contracts import AssessmentClauseReference
from app.models.reports import (
    CitationValidationStatus,
    ValidatedStandardReference,
)
from app.models.retrieval import KnowledgeChunk, KnowledgeLookup
from app.providers.interfaces import KnowledgeRetriever
from app.services.knowledge_index import build_knowledge_chunks


logger = logging.getLogger(__name__)


class CitationValidator:
    def __init__(
        self,
        retriever: KnowledgeRetriever,
        *,
        canonical_chunks: tuple[KnowledgeChunk, ...] | None = None,
        enforce_review_status: bool = False,
    ) -> None:
        self._retriever = retriever
        self._enforce_review_status = enforce_review_status
        if canonical_chunks is None:
            _, canonical_chunks = build_knowledge_chunks()
        self._canonical_by_point_id = {
            chunk.point_id: chunk for chunk in canonical_chunks
        }
        self._cache: dict[tuple[str, str], tuple] = {}

    async def validate(
        self,
        reference: AssessmentClauseReference,
    ) -> ValidatedStandardReference:
        key = (reference.standard_code, reference.clause_id)
        try:
            if key not in self._cache:
                self._cache[key] = await self._retriever.retrieve_exact(
                    lookup=KnowledgeLookup(
                        standard_code=reference.standard_code,
                        clause_id=reference.clause_id,
                        limit=100,
                    )
                )
            candidates = self._cache[key]
        except Exception:
            logger.exception(
                "citation retrieval unavailable",
                extra={
                    "standard_code": reference.standard_code,
                    "clause_id": reference.clause_id,
                },
            )
            return self._result(
                reference,
                CitationValidationStatus.RETRIEVER_UNAVAILABLE,
                "标准知识索引不可用，未输出标准原文。",
            )

        if not candidates:
            return self._result(
                reference,
                CitationValidationStatus.MISSING,
                "标准知识索引中没有匹配的标准号和条款号。",
            )

        review_status_blocked = False
        provenance_mismatch = False
        for candidate in candidates:
            chunk = candidate.chunk
            if reference.record_id and chunk.record_id != reference.record_id:
                continue
            canonical = self._canonical_by_point_id.get(chunk.point_id)
            if canonical is None or canonical != chunk:
                return self._result(
                    reference,
                    CitationValidationStatus.PAYLOAD_MISMATCH,
                    "检索载荷与版本化目录不一致，未输出标准原文。",
                )
            if not chunk.citation_eligible:
                continue
            if (
                reference.classified_protection_level
                not in chunk.classified_protection_levels
                or reference.printed_pages != chunk.printed_pages
                or reference.pdf_page_indexes != chunk.pdf_page_indexes
            ):
                provenance_mismatch = True
                continue
            if self._enforce_review_status and chunk.review_status not in {
                "HumanReviewed",
                "Approved",
            }:
                review_status_blocked = True
                continue
            if self._enforce_review_status:
                validation_message = (
                    "标准原文已通过目录身份、内容哈希和审核状态校验。"
                )
            else:
                validation_message = (
                    "标准原文已通过目录身份和内容哈希校验；"
                    "当前未启用审核状态门禁。"
                )
            return ValidatedStandardReference(
                standard_code=reference.standard_code,
                clause_id=reference.clause_id,
                classified_protection_level=reference.classified_protection_level,
                printed_pages=reference.printed_pages,
                pdf_page_indexes=reference.pdf_page_indexes,
                validation_status=CitationValidationStatus.VALID,
                validation_message=validation_message,
                record_id=chunk.record_id,
                point_id=chunk.point_id,
                source_catalog_id=chunk.source_catalog_id,
                source_record_pointer=chunk.source_record_pointer,
                content_sha256=chunk.content_sha256,
                text_kind=chunk.text_kind,
                standard_text=chunk.text,
            )

        if provenance_mismatch:
            return self._result(
                reference,
                CitationValidationStatus.PAYLOAD_MISMATCH,
                "匹配原文的等保等级或页码元数据与规则引用不一致，未输出标准原文。",
            )

        if review_status_blocked:
            return self._result(
                reference,
                CitationValidationStatus.NOT_CITABLE,
                "匹配原文未通过正式审核状态门禁，未输出标准原文。",
            )

        return self._result(
            reference,
            CitationValidationStatus.NOT_CITABLE,
            "匹配记录仅为摘要或测评整理数据，不能作为标准原文引用。",
        )

    @staticmethod
    def _result(
        reference: AssessmentClauseReference,
        status: CitationValidationStatus,
        message: str,
    ) -> ValidatedStandardReference:
        return ValidatedStandardReference(
            standard_code=reference.standard_code,
            clause_id=reference.clause_id,
            classified_protection_level=reference.classified_protection_level,
            printed_pages=reference.printed_pages,
            pdf_page_indexes=reference.pdf_page_indexes,
            validation_status=status,
            validation_message=message,
        )
