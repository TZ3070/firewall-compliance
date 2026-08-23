from __future__ import annotations

import argparse
import json
import re
from copy import deepcopy
from datetime import date
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree
from zipfile import ZipFile


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REVIEW_PATH = (
    PROJECT_ROOT
    / "outputs"
    / "verbatim-extraction"
    / "standard-verbatim-review-v1.xlsx"
)
DEFAULT_CANDIDATE_PATH = (
    PROJECT_ROOT
    / "backend"
    / "data"
    / "catalog"
    / "verbatim-extraction-candidates-v1.json"
)
DEFAULT_UNIFIED_CATALOG_PATH = (
    PROJECT_ROOT
    / "backend"
    / "data"
    / "catalog"
    / "unified-firewall-catalog-v1.json"
)
DEFAULT_OUTPUT_PATH = (
    PROJECT_ROOT
    / "backend"
    / "data"
    / "catalog"
    / "reviewed-verbatim-catalog-v1.json"
)

MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PACKAGE_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
CELL_REF = re.compile(r"([A-Z]+)(\d+)")

REVIEW_HEADERS = (
    "record_id",
    "standard_code",
    "record_type",
    "title",
    "machine_extraction_status",
    "excerpt_count",
    "reference_labels",
    "issues",
    "reviewer_decision",
    "reviewer_notes",
    "excerpts_sha256",
)
EXCERPT_HEADERS = (
    "record_id",
    "standard_code",
    "record_type",
    "excerpt_no",
    "reference_label",
    "classified_protection_level",
    "printed_pages",
    "pdf_page_indexes",
    "verbatim_candidate_text",
    "content_sha256",
)


def _sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _column_index(cell_reference: str) -> int:
    match = CELL_REF.fullmatch(cell_reference)
    if match is None:
        raise ValueError(f"invalid cell reference: {cell_reference}")
    value = 0
    for character in match.group(1):
        value = value * 26 + ord(character) - ord("A") + 1
    return value - 1


def _shared_strings(archive: ZipFile) -> tuple[str, ...]:
    path = "xl/sharedStrings.xml"
    if path not in archive.namelist():
        return ()
    root = ElementTree.fromstring(archive.read(path))
    namespace = {"x": MAIN_NS}
    return tuple(
        "".join(node.itertext()) for node in root.findall("x:si", namespace)
    )


def _worksheet_path(archive: ZipFile, sheet_name: str) -> str:
    namespace = {"x": MAIN_NS, "r": REL_NS}
    workbook = ElementTree.fromstring(archive.read("xl/workbook.xml"))
    relation_id = None
    for sheet in workbook.findall("x:sheets/x:sheet", namespace):
        if sheet.attrib.get("name") == sheet_name:
            relation_id = sheet.attrib.get(f"{{{REL_NS}}}id")
            break
    if relation_id is None:
        raise ValueError(f"review workbook is missing sheet: {sheet_name}")

    relationships = ElementTree.fromstring(
        archive.read("xl/_rels/workbook.xml.rels")
    )
    target = None
    for relationship in relationships.findall(f"{{{PACKAGE_REL_NS}}}Relationship"):
        if relationship.attrib.get("Id") == relation_id:
            target = relationship.attrib.get("Target")
            break
    if not target:
        raise ValueError(f"review workbook cannot resolve sheet: {sheet_name}")
    if target.startswith("/"):
        return target.lstrip("/")
    return str(PurePosixPath("xl") / target)


def _cell_value(cell: ElementTree.Element, shared: tuple[str, ...]) -> str:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        inline = cell.find(f"{{{MAIN_NS}}}is")
        return "" if inline is None else "".join(inline.itertext())
    raw = cell.findtext(f"{{{MAIN_NS}}}v", default="")
    if cell_type == "s" and raw:
        return shared[int(raw)]
    return raw


def read_worksheet(review_path: Path, sheet_name: str) -> tuple[tuple[str, ...], ...]:
    with ZipFile(review_path) as archive:
        shared = _shared_strings(archive)
        root = ElementTree.fromstring(
            archive.read(_worksheet_path(archive, sheet_name))
        )
    rows: list[tuple[str, ...]] = []
    for row in root.findall(f".//{{{MAIN_NS}}}sheetData/{{{MAIN_NS}}}row"):
        values: dict[int, str] = {}
        for cell in row.findall(f"{{{MAIN_NS}}}c"):
            reference = cell.attrib.get("r")
            if reference:
                values[_column_index(reference)] = _cell_value(cell, shared)
        width = max(values, default=-1) + 1
        rows.append(tuple(values.get(index, "") for index in range(width)))
    return tuple(rows)


def _padded(row: tuple[str, ...], width: int) -> tuple[str, ...]:
    return (*row, *("" for _ in range(max(width - len(row), 0))))[:width]


def _reference_label(excerpt: dict[str, Any]) -> str:
    measurement_id = excerpt.get("measurement_unit_id")
    if measurement_id:
        return str(measurement_id)
    clause_id = str(excerpt.get("clause_id", "")).strip()
    selector = str(excerpt.get("requested_item_selector") or "").strip()
    return " ".join(part for part in (clause_id, selector) if part)


def validate_review_rows(
    candidate_payload: dict[str, Any],
    review_rows: tuple[tuple[str, ...], ...],
    excerpt_rows: tuple[tuple[str, ...], ...],
) -> dict[str, dict[str, str]]:
    if not review_rows or _padded(review_rows[0], len(REVIEW_HEADERS)) != REVIEW_HEADERS:
        raise ValueError("审核总表表头与发布器版本不匹配")
    if not excerpt_rows or _padded(excerpt_rows[0], len(EXCERPT_HEADERS)) != EXCERPT_HEADERS:
        raise ValueError("提取原文表头与发布器版本不匹配")

    candidates = {record["record_id"]: record for record in candidate_payload["records"]}
    decisions: dict[str, dict[str, str]] = {}
    for row_number, raw_row in enumerate(review_rows[1:], start=2):
        row = _padded(raw_row, len(REVIEW_HEADERS))
        record_id, decision, notes = row[0].strip(), row[8].strip(), row[9].strip()
        if not record_id:
            continue
        if record_id in decisions:
            raise ValueError(f"审核总表 record_id 重复: {record_id}")
        record = candidates.get(record_id)
        if record is None:
            raise ValueError(f"审核总表存在未知 record_id: {record_id}")
        if decision not in {"Approved", "Rejected"}:
            raise ValueError(
                f"审核总表第 {row_number} 行尚未完成审核: {decision or '<blank>'}"
            )
        if decision == "Rejected" and not notes:
            raise ValueError(f"审核总表第 {row_number} 行 Rejected 但未填写原因")
        expected_hashes = "|".join(
            excerpt["content_sha256"] for excerpt in record["excerpts"]
        )
        if row[10] != expected_hashes:
            raise ValueError(f"审核总表摘录哈希不匹配: {record_id}")
        if row[5] != str(len(record["excerpts"])):
            raise ValueError(f"审核总表摘录数量不匹配: {record_id}")
        decisions[record_id] = {"status": decision, "notes": notes}

    missing = set(candidates) - set(decisions)
    if missing:
        raise ValueError(f"审核总表缺少 {len(missing)} 条记录")

    expected_excerpts = {
        (record["record_id"], str(index)): excerpt
        for record in candidate_payload["records"]
        for index, excerpt in enumerate(record["excerpts"], start=1)
    }
    seen_excerpts: set[tuple[str, str]] = set()
    for row_number, raw_row in enumerate(excerpt_rows[1:], start=2):
        row = _padded(raw_row, len(EXCERPT_HEADERS))
        if not row[0].strip():
            continue
        key = (row[0].strip(), row[3].strip())
        if key in seen_excerpts:
            raise ValueError(f"提取原文表存在重复摘录: {key}")
        expected = expected_excerpts.get(key)
        if expected is None:
            raise ValueError(f"提取原文表存在未知摘录: {key}")
        if row[8] != expected["text"] or row[9] != expected["content_sha256"]:
            raise ValueError(f"提取原文表原文或哈希不匹配: {key}")
        seen_excerpts.add(key)
    missing_excerpts = set(expected_excerpts) - seen_excerpts
    if missing_excerpts:
        raise ValueError(f"提取原文表缺少 {len(missing_excerpts)} 段摘录")
    return decisions


def build_reviewed_catalog(
    *,
    candidate_payload: dict[str, Any],
    unified_payload: dict[str, Any],
    decisions: dict[str, dict[str, str]],
    review_file_name: str,
    review_sha256: str,
    reviewed_on: str,
) -> dict[str, Any]:
    unified_records = {
        record["record_id"]: record
        for record in (
            *unified_payload["controls"],
            *unified_payload["measurement_units"],
        )
    }
    source_hashes = {
        source["catalog_id"]: source["sha256"] for source in unified_payload["sources"]
    }
    approved_records: list[dict[str, Any]] = []
    rejected_records: list[dict[str, str]] = []
    for record in candidate_payload["records"]:
        decision = decisions[record["record_id"]]
        if decision["status"] == "Rejected":
            rejected_records.append(
                {"record_id": record["record_id"], "notes": decision["notes"]}
            )
            continue
        unified = unified_records.get(record["record_id"])
        if unified is None:
            raise ValueError(f"统一目录缺少 record_id: {record['record_id']}")
        published = deepcopy(record)
        published.update(
            {
                "review_status": "HumanReviewed",
                "citation_eligible": True,
                "text_kind": "verbatim",
                "source_catalog_sha256": source_hashes[record["source_catalog_id"]],
                "topic": unified.get("topic"),
                "context": unified.get("context"),
                "search_text": unified["search_text"],
                "review_decision": {
                    "status": "Approved",
                    "reviewed_on": reviewed_on,
                    "review_artifact_sha256": review_sha256,
                    "notes": decision["notes"],
                },
            }
        )
        for excerpt in published["excerpts"]:
            if sha256(excerpt["text"].encode("utf-8")).hexdigest() != excerpt["content_sha256"]:
                raise ValueError(f"原文哈希不匹配: {record['record_id']}")
        approved_records.append(published)

    return {
        "schema_version": "1.0.0",
        "catalog_id": "bank-firewall-reviewed-verbatim-v1",
        "catalog_version": "1.0.0",
        "generated_on": reviewed_on,
        "scope": "由人工审核通过的防火墙相关标准原文，可用于可追溯引用与定向检索。",
        "source_candidate_catalog": {
            "catalog_id": candidate_payload["catalog_id"],
            "catalog_version": candidate_payload["catalog_version"],
        },
        "source_unified_catalog": candidate_payload["source_unified_catalog"],
        "review_artifact": {
            "file_name": review_file_name,
            "sha256": review_sha256,
            "reviewed_on": reviewed_on,
            "approved_count": len(approved_records),
            "rejected_count": len(rejected_records),
        },
        "sources": candidate_payload["sources"],
        "record_count": len(approved_records),
        "excerpt_count": sum(len(record["excerpts"]) for record in approved_records),
        "records": approved_records,
        "rejected_records": rejected_records,
    }


def publish(
    *,
    review_path: Path = DEFAULT_REVIEW_PATH,
    candidate_path: Path = DEFAULT_CANDIDATE_PATH,
    unified_catalog_path: Path = DEFAULT_UNIFIED_CATALOG_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    reviewed_on: str | None = None,
) -> dict[str, Any]:
    candidate_payload = json.loads(candidate_path.read_text(encoding="utf-8"))
    unified_payload = json.loads(unified_catalog_path.read_text(encoding="utf-8"))
    expected_unified_hash = candidate_payload["source_unified_catalog"]["sha256"]
    if _sha256(unified_catalog_path) != expected_unified_hash:
        raise ValueError("统一目录哈希与原文候选绑定值不一致")
    decisions = validate_review_rows(
        candidate_payload,
        read_worksheet(review_path, "审核总表"),
        read_worksheet(review_path, "提取原文"),
    )
    review_hash = _sha256(review_path)
    payload = build_reviewed_catalog(
        candidate_payload=candidate_payload,
        unified_payload=unified_payload,
        decisions=decisions,
        review_file_name=review_path.name,
        review_sha256=review_hash,
        reviewed_on=reviewed_on or date.today().isoformat(),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="验证人工审核表并发布可引用标准原文目录。"
    )
    parser.add_argument("--review", type=Path, default=DEFAULT_REVIEW_PATH)
    parser.add_argument("--candidates", type=Path, default=DEFAULT_CANDIDATE_PATH)
    parser.add_argument("--unified-catalog", type=Path, default=DEFAULT_UNIFIED_CATALOG_PATH)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--reviewed-on", default=None)
    args = parser.parse_args()
    payload = publish(
        review_path=args.review,
        candidate_path=args.candidates,
        unified_catalog_path=args.unified_catalog,
        output_path=args.output,
        reviewed_on=args.reviewed_on,
    )
    print(f"published {payload['record_count']} reviewed records")
    print(f"published {payload['excerpt_count']} citable excerpts")
    print(f"output={args.output}")


if __name__ == "__main__":
    main()
