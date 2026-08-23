from scripts.extract_verbatim_candidates import (
    Block,
    _expand_item_selector,
    _heading_id,
    _parse_references,
    _select_section_text,
)


def test_heading_parser_distinguishes_spaced_two_digit_suffix() -> None:
    assert _heading_id("8 . 1 . 4 . 1      身份鉴别") == "8.1.4.1"
    assert _heading_id("8 . 1 . 4 . 1 1    个人信息保护") == "8.1.4.11"


def test_reference_parser_splits_compound_clause_and_item_ranges() -> None:
    parsed = _parse_references(
        {
            "clause_id": "7.1.4.9 a-b；7.1.5.1 f",
            "item": None,
        }
    )

    assert [(item.clause_id, item.item_selector) for item in parsed] == [
        ("7.1.4.9", "a-b"),
        ("7.1.5.1", "f"),
    ]
    assert _expand_item_selector("a-b,e-f,i") == ("a", "b", "e", "f", "i")


def test_item_selector_returns_only_requested_verbatim_items() -> None:
    section = (
        Block(0, "8.1.3.3   入侵防范", "paragraph", "8.1.3.3"),
        Block(1, "本项要求包括：", "paragraph", None),
        Block(2, "a) 外部攻击要求。", "paragraph", None),
        Block(3, "b) 内部攻击要求。", "paragraph", None),
        Block(4, "c) 其他要求。", "paragraph", None),
    )

    text, found, missing = _select_section_text(section, "a-b")

    assert found == ("a", "b")
    assert missing == ()
    assert "外部攻击要求" in text
    assert "内部攻击要求" in text
    assert "其他要求" not in text
