from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable

from docx import Document
from docx.document import Document as DocumentObject
from docx.oxml.table import CT_Tbl
from docx.oxml.text.paragraph import CT_P
from docx.table import Table
from docx.text.paragraph import Paragraph


BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
DEFAULT_CATALOG_PATH = (
    BACKEND_ROOT / "data" / "catalog" / "unified-firewall-catalog-v1.json"
)
DEFAULT_OUTPUT_PATH = (
    BACKEND_ROOT / "data" / "catalog" / "verbatim-extraction-candidates-v1.json"
)
DEFAULT_REVIEW_CSV_PATH = (
    PROJECT_ROOT / "docs" / "verbatim-extraction-review-v1.csv"
)
DEFAULT_SUMMARY_PATH = PROJECT_ROOT / "docs" / "verbatim-extraction-summary-v1.md"

STANDARD_DOCX_FILES = {
    "GB/T 20281—2020": "GB-T-20281-2020-防火墙安全技术要求和测试评价方法.docx",
    "GB/T 22239—2019": "GB-T-22239-2019-网络安全等级保护基本要求.docx",
    "JR/T 0071.2—2020": "JR-T-0071.2-2020-基本要求.docx",
    "JR/T 0072—2020": "JR-T-0072-2020-测评指南.docx",
}

HEADING_RE = re.compile(r"^(\d+(?:\.\d+)+)(?:\s+|$)")
REFERENCE_RE = re.compile(r"^(\d+(?:\.\d+)+)(?:\s+(.+))?$")
ITEM_RE = re.compile(r"^([a-z])\s*[)）.]\s*", re.IGNORECASE)
UNIT_RE = re.compile(r"测评单元[（(]\s*([^）)]+?)\s*[）)]")


@dataclass(frozen=True)
class Block:
    index: int
    text: str
    kind: str
    heading_id: str | None


@dataclass(frozen=True)
class ParsedReference:
    clause_id: str
    item_selector: str | None


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _normalize_heading_text(text: str) -> str:
    return re.sub(r"\s*\.\s*", ".", text.strip())


def _heading_id(text: str) -> str | None:
    spaced_match = re.match(r"^([0-9][0-9.\s]*[0-9])\s{2,}\S", text.strip())
    if spaced_match:
        compact_number = re.sub(r"\s+", "", spaced_match.group(1))
        if re.fullmatch(r"\d+(?:\.\d+)+", compact_number):
            return compact_number
    match = HEADING_RE.match(_normalize_heading_text(text))
    return match.group(1) if match else None


def _table_text(table: Table) -> str:
    rows: list[str] = []
    for row in table.rows:
        cells = [" ".join(cell.text.split()) for cell in row.cells]
        if any(cells):
            rows.append(" | ".join(cells))
    return "\n".join(rows)


def _document_blocks(path: Path) -> tuple[Block, ...]:
    document = Document(path)
    blocks: list[Block] = []
    for child in document.element.body.iterchildren():
        if isinstance(child, CT_P):
            text = Paragraph(child, document).text.strip()
            kind = "paragraph"
        elif isinstance(child, CT_Tbl):
            text = _table_text(Table(child, document))
            kind = "table"
        else:
            continue
        if not text:
            continue
        blocks.append(
            Block(
                index=len(blocks),
                text=text,
                kind=kind,
                heading_id=_heading_id(text) if kind == "paragraph" else None,
            )
        )
    return tuple(blocks)


def _section_candidates(
    blocks: tuple[Block, ...], clause_id: str
) -> tuple[tuple[Block, ...], ...]:
    starts = [block.index for block in blocks if block.heading_id == clause_id]
    depth = clause_id.count(".") + 1
    candidates: list[tuple[Block, ...]] = []
    for start in starts:
        end = len(blocks)
        for block in blocks[start + 1 :]:
            if block.heading_id and block.heading_id.count(".") + 1 <= depth:
                end = block.index
                break
        candidates.append(blocks[start:end])
    return tuple(candidates)


def _best_section(
    blocks: tuple[Block, ...], clause_id: str
) -> tuple[tuple[Block, ...] | None, int]:
    candidates = _section_candidates(blocks, clause_id)
    if not candidates:
        return None, 0
    return max(candidates, key=lambda value: sum(len(x.text) for x in value)), len(
        candidates
    )


def _parse_references(reference: dict[str, object]) -> tuple[ParsedReference, ...]:
    values: list[ParsedReference] = []
    explicit_item = reference.get("item")
    segments = re.split(r"[；;]", str(reference["clause_id"]))
    for index, raw_segment in enumerate(segments):
        segment = _normalize_heading_text(raw_segment)
        match = REFERENCE_RE.fullmatch(segment)
        if match is None:
            raise ValueError(f"unparseable clause reference: {raw_segment!r}")
        selector = match.group(2)
        if selector is None and explicit_item and len(segments) == 1:
            selector = str(explicit_item)
        values.append(
            ParsedReference(
                clause_id=match.group(1),
                item_selector=selector.strip() if selector else None,
            )
        )
    return tuple(values)


def _expand_item_selector(selector: str) -> tuple[str, ...]:
    selected: list[str] = []
    for token in re.split(r"[,，、]", selector.lower().replace(" ", "")):
        if not token:
            continue
        if re.fullmatch(r"[a-z]-[a-z]", token):
            start, end = token.split("-")
            selected.extend(chr(value) for value in range(ord(start), ord(end) + 1))
        elif re.fullmatch(r"[a-z]", token):
            selected.append(token)
        else:
            raise ValueError(f"unsupported item selector: {selector!r}")
    return tuple(dict.fromkeys(selected))


def _select_section_text(
    section: tuple[Block, ...], item_selector: str | None
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    if item_selector is None:
        text = "\n".join(block.text for block in section).strip()
        return text, (), ()

    wanted = _expand_item_selector(item_selector)
    groups: dict[str, list[str]] = {}
    current_item: str | None = None
    for block in section[1:]:
        match = ITEM_RE.match(block.text)
        if match:
            current_item = match.group(1).lower()
            groups.setdefault(current_item, []).append(block.text)
        elif current_item is not None:
            groups[current_item].append(block.text)

    found = tuple(item for item in wanted if item in groups)
    missing = tuple(item for item in wanted if item not in groups)
    selected_lines = [section[0].text]
    for item in found:
        selected_lines.extend(groups[item])
    return "\n".join(selected_lines).strip(), found, missing


def _control_excerpts(
    control: dict[str, object],
    blocks: tuple[Block, ...],
) -> tuple[list[dict[str, object]], list[str]]:
    excerpts: list[dict[str, object]] = []
    issues: list[str] = []
    references = control["source_references"]
    assert isinstance(references, list)
    for reference_index, reference_value in enumerate(references):
        assert isinstance(reference_value, dict)
        for parsed in _parse_references(reference_value):
            section, occurrence_count = _best_section(blocks, parsed.clause_id)
            if section is None:
                issues.append(f"MISSING_CLAUSE:{parsed.clause_id}")
                continue
            text, found_items, missing_items = _select_section_text(
                section, parsed.item_selector
            )
            if occurrence_count > 1:
                issues.append(
                    f"DUPLICATE_CLAUSE_HEADING:{parsed.clause_id}:{occurrence_count}"
                )
            if missing_items:
                issues.append(
                    f"MISSING_ITEMS:{parsed.clause_id}:{','.join(missing_items)}"
                )
            excerpts.append(
                {
                    "reference_index": reference_index,
                    "relation": reference_value.get("relation"),
                    "clause_id": parsed.clause_id,
                    "requested_item_selector": parsed.item_selector,
                    "extracted_items": list(found_items),
                    "classified_protection_level": reference_value.get(
                        "classified_protection_level"
                    ),
                    "printed_pages": reference_value.get("printed_pages", []),
                    "pdf_page_indexes": reference_value.get("pdf_page_indexes", []),
                    "text": text,
                    "content_sha256": _sha256_text(text),
                    "source_heading_occurrences": occurrence_count,
                }
            )
    return excerpts, list(dict.fromkeys(issues))


def _measurement_markers(
    blocks: tuple[Block, ...],
) -> dict[tuple[str, str], tuple[int, ...]]:
    current_heading: str | None = None
    values: dict[tuple[str, str], list[int]] = {}
    for block in blocks:
        if block.heading_id:
            current_heading = block.heading_id
        match = UNIT_RE.search(block.text)
        if match and current_heading:
            key = (current_heading, match.group(1).strip())
            values.setdefault(key, []).append(block.index)
    return {key: tuple(indexes) for key, indexes in values.items()}


def _measurement_excerpt(
    unit: dict[str, object],
    blocks: tuple[Block, ...],
    markers: dict[tuple[str, str], tuple[int, ...]],
) -> tuple[list[dict[str, object]], list[str]]:
    guide_clause_id = str(unit["guide_clause_id"])
    unit_id = str(unit["source_measurement_unit_id"])
    starts = markers.get((guide_clause_id, unit_id), ())
    if len(starts) != 1:
        issue = "MISSING_MEASUREMENT_UNIT" if not starts else "DUPLICATE_MEASUREMENT_UNIT"
        return [], [f"{issue}:{guide_clause_id}:{unit_id}:{len(starts)}"]

    start = starts[0]
    depth = guide_clause_id.count(".") + 1
    end = len(blocks)
    for block in blocks[start + 1 :]:
        if UNIT_RE.search(block.text):
            end = block.index
            break
        if block.heading_id and block.heading_id.count(".") + 1 <= depth:
            end = block.index
            break
    text = "\n".join(block.text for block in blocks[start:end]).strip()
    return [
        {
            "guide_clause_id": guide_clause_id,
            "measurement_unit_id": unit_id,
            "classified_protection_level": unit.get(
                "classified_protection_level"
            ),
            "printed_pages": unit.get("printed_pages", []),
            "pdf_page_indexes": unit.get("pdf_page_indexes", []),
            "text": text,
            "content_sha256": _sha256_text(text),
            "source_heading_occurrences": 1,
        }
    ], []


def _record_title(record: dict[str, object]) -> str:
    if record["record_type"] == "measurement-unit":
        return f'{record["canonical_measurement_unit_id"]} 测评单元'
    return str(record["title"])


def _write_review_csv(path: Path, records: Iterable[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = (
        "record_id",
        "standard_code",
        "record_type",
        "title",
        "machine_extraction_status",
        "excerpt_count",
        "reference_labels",
        "extracted_text",
        "issues",
        "reviewer_decision",
        "reviewer_notes",
    )
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for record in records:
            excerpts = record["excerpts"]
            assert isinstance(excerpts, list)
            labels = [
                str(
                    excerpt.get("measurement_unit_id")
                    or " ".join(
                        value
                        for value in (
                            str(excerpt.get("clause_id", "")),
                            str(excerpt.get("requested_item_selector") or ""),
                        )
                        if value
                    )
                )
                for excerpt in excerpts
            ]
            writer.writerow(
                {
                    "record_id": record["record_id"],
                    "standard_code": record["standard_code"],
                    "record_type": record["record_type"],
                    "title": record["title"],
                    "machine_extraction_status": record["machine_extraction_status"],
                    "excerpt_count": len(excerpts),
                    "reference_labels": " | ".join(labels),
                    "extracted_text": "\n\n--- EXCERPT ---\n\n".join(
                        str(excerpt["text"]) for excerpt in excerpts
                    ),
                    "issues": " | ".join(str(x) for x in record["issues"]),
                    "reviewer_decision": "",
                    "reviewer_notes": "",
                }
            )


def _write_summary(
    path: Path,
    *,
    records: list[dict[str, object]],
    sources: list[dict[str, object]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    matched = sum(
        record["machine_extraction_status"] == "Extracted"
        for record in records
    )
    issue_records = [record for record in records if record["issues"]]
    lines = [
        "# 标准原文机器提取审核说明",
        "",
        f"- 目录记录：{len(records)} 条",
        f"- 成功提取：{matched} 条",
        f"- 含异常：{len(issue_records)} 条",
        "- 审核状态：全部 PendingHumanReview",
        "- citation_eligible：全部 false（审核前不允许正式引用）",
        "",
        "## 来源 Word 文件",
        "",
    ]
    for source in sources:
        lines.append(
            f'- {source["standard_code"]}：`{source["file_name"]}`，'
            f'SHA-256 `{source["docx_sha256"]}`'
        )
    lines.extend(
        [
            "",
            "## 审核方法",
            "",
            "1. 在 CSV 中按 record_id 逐条对照 Word。",
            "2. reviewer_decision 只填 Approved 或 Rejected。",
            "3. 条款号、子项、原文或版本任一不一致时填 Rejected，并在 reviewer_notes 说明。",
            "4. 不要直接修改机器提取 JSON；审核决定应另存为版本化决定文件。",
            "",
            "## 异常记录",
            "",
        ]
    )
    if not issue_records:
        lines.append("无。")
    else:
        for record in issue_records:
            lines.append(
                f'- `{record["record_id"]}`: {", ".join(record["issues"])}'
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def extract(
    *,
    catalog_path: Path,
    docx_root: Path,
    output_path: Path,
    review_csv_path: Path,
    summary_path: Path,
) -> dict[str, object]:
    raw_catalog = catalog_path.read_bytes()
    catalog = json.loads(raw_catalog)
    documents: dict[str, tuple[Block, ...]] = {}
    sources: list[dict[str, object]] = []
    for standard_code, file_name in STANDARD_DOCX_FILES.items():
        path = docx_root / file_name
        payload = path.read_bytes()
        documents[standard_code] = _document_blocks(path)
        sources.append(
            {
                "standard_code": standard_code,
                "file_name": file_name,
                "file_size_bytes": len(payload),
                "docx_sha256": _sha256_bytes(payload),
            }
        )

    measurement_blocks = documents["JR/T 0072—2020"]
    measurement_markers = _measurement_markers(measurement_blocks)
    records: list[dict[str, object]] = []
    source_records = [*catalog["controls"], *catalog["measurement_units"]]
    for source_record in source_records:
        standard_code = source_record["standard_code"]
        if source_record["record_type"] == "measurement-unit":
            excerpts, issues = _measurement_excerpt(
                source_record, measurement_blocks, measurement_markers
            )
        else:
            excerpts, issues = _control_excerpts(
                source_record, documents[standard_code]
            )
        records.append(
            {
                "record_id": source_record["record_id"],
                "record_type": source_record["record_type"],
                "standard_code": standard_code,
                "title": _record_title(source_record),
                "source_catalog_id": source_record["source_catalog_id"],
                "source_record_pointer": source_record["source_record_pointer"],
                "machine_extraction_status": (
                    "Extracted" if excerpts and not issues else "NeedsReview"
                ),
                "review_status": "PendingHumanReview",
                "citation_eligible": False,
                "text_kind": "verbatim-candidate",
                "issues": issues,
                "excerpts": excerpts,
            }
        )

    payload = {
        "schema_version": "1.0.0",
        "catalog_id": "bank-firewall-verbatim-extraction-candidates-v1",
        "catalog_version": "1.0.0",
        "generated_on": date.today().isoformat(),
        "extraction_method": "reviewed-docx-structure/v1",
        "source_unified_catalog": {
            "path": str(catalog_path),
            "sha256": _sha256_bytes(raw_catalog),
        },
        "scope": (
            "440 条统一目录记录的 Word 原文机器提取候选；"
            "未经人工审核，不可作为正式标准原文引用。"
        ),
        "sources": sources,
        "record_count": len(records),
        "records": records,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    _write_review_csv(review_csv_path, records)
    _write_summary(summary_path, records=records, sources=sources)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract 440 pending-review verbatim candidates from reviewed DOCX files."
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=DEFAULT_CATALOG_PATH,
    )
    parser.add_argument("--docx-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--review-csv", type=Path, default=DEFAULT_REVIEW_CSV_PATH)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY_PATH)
    args = parser.parse_args()
    payload = extract(
        catalog_path=args.catalog.resolve(),
        docx_root=args.docx_root.resolve(),
        output_path=args.output.resolve(),
        review_csv_path=args.review_csv.resolve(),
        summary_path=args.summary.resolve(),
    )
    records = payload["records"]
    assert isinstance(records, list)
    extracted = sum(
        record["machine_extraction_status"] == "Extracted" for record in records
    )
    print(f"records={len(records)} extracted={extracted} needs_review={len(records)-extracted}")
    print(f"output={args.output.resolve()}")
    print(f"review_csv={args.review_csv.resolve()}")
    print(f"summary={args.summary.resolve()}")


if __name__ == "__main__":
    main()
