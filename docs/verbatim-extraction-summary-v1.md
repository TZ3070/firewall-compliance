# 标准原文机器提取审核说明

- 目录记录：440 条
- 成功提取：440 条
- 含异常：0 条
- 审核状态：全部 PendingHumanReview
- citation_eligible：全部 false（审核前不允许正式引用）

## 来源 Word 文件

- GB/T 20281—2020：`GB-T-20281-2020-防火墙安全技术要求和测试评价方法.docx`，SHA-256 `c957341d2678644f0262c07aa459b52473dde852f0cd7884337e1a1b441ad226`
- GB/T 22239—2019：`GB-T-22239-2019-网络安全等级保护基本要求.docx`，SHA-256 `8565229599750a62f3bb9a60427ff033bc6ceb9a102b49b4cb6a45697b3713fc`
- JR/T 0071.2—2020：`JR-T-0071.2-2020-基本要求.docx`，SHA-256 `1f672ebe5b25becb308ab3f274cf29c67e6d314f96e975f3e445b9deb998fe55`
- JR/T 0072—2020：`JR-T-0072-2020-测评指南.docx`，SHA-256 `9be87e888706afb999d6bac2ce07266ba61f32b2793035862fdc7034484d3d2c`

## 审核方法

1. 在 CSV 中按 record_id 逐条对照 Word。
2. reviewer_decision 只填 Approved 或 Rejected。
3. 条款号、子项、原文或版本任一不一致时填 Rejected，并在 reviewer_notes 说明。
4. 不要直接修改机器提取 JSON；审核决定应另存为版本化决定文件。

## 异常记录

无。
