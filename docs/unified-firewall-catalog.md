# 防火墙统一目录 v1

## 目标

统一目录将四份标准整理结果转换为同一检索契约，同时保留源目录和 JSON Pointer，避免规范化过程覆盖原始证据。

## 数据规模

- 要求控制项：110 条，其中 GB/T 22239—2019 为 47 条、JR/T 0071.2—2020 为 63 条。
- 产品控制项：47 条，来自 GB/T 20281—2020。
- 测评单元：283 个，来自 JR/T 0072—2020。
- 测评单元到要求控制项的关系：291 条。

## 场景规范

`context` 只允许使用当前目录中已出现的规范值：

- `general`
- `cloud`
- `mobile`
- `iot`
- `industrial-control`

是否条件适用由独立的 `conditional` 布尔字段表示。源目录中的 `cloud-conditional`、`mobile-conditional` 和 `iot-conditional` 不会直接进入统一过滤字段。

## 人工复核与异常

人工确认记录保存在 `backend/data/catalog/unified-catalog-review-decisions.json`。统一目录保留四条历史异常记录，并通过 `resolution_status` 和 `resolution_decision_id` 关联处理决定。

- 两条“鉴别密钥/认证密钥”映射已经人工确认，关系状态为 `HumanReviewed`。
- `L3-CES1-03` 到 `JR0071-2-FW-026` 是部分覆盖，关系字段为 `coverage: partial`、`blocks_standalone_pass: true`。
- 第四级章节原文 `L3-ABS3-03` 的规范编号为 `L4-ABS3-03`。原始复合键保存在 `record_aliases` 和顶层 `aliases` 中。

## 使用边界

当前四份源目录仍为 `Candidate`，所以目录中保留 `review_gate.final_determination_allowed=false`。P0 暂时不执行这个 `review_status` 门禁：`Candidate` 记录可以用于索引、检索、映射、候选评估和当前配置匹配，且不因审核状态单独阻断 Passed/Failed。

P0 例外只是忽略审核状态的阻断作用，不会改写源数据，也不允许把 `requirement_summary`、`search_text` 或测评整理文本当作标准逐字原文。页面和报告必须继续显示实际审核状态及 P0 限制；非 P0 正式发布前仍需完成人工复核并恢复门禁。

重新生成目录：

```bash
cd backend
.venv/bin/python scripts/build_unified_catalog.py
```
