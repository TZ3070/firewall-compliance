# 系统骨架

## 1. 模块与目录

```text
backend/app/
├── api/             # HTTP 路由、请求/响应边界
├── agent/           # 最多6步的受控 ReAct 循环、意图路由与工具策略
├── core/            # 配置、错误码、安全公共能力
├── models/          # Pydantic 核心数据结构
├── providers/       # Mock 配置、Qdrant Local、FastEmbed 的适配接口
├── repositories/    # SQLite 持久化接口
├── rules/           # 12 条高置信度确定性规则
└── services/        # 配置、引用、报告等可受控调用的用例

frontend/src/
├── api/             # FastAPI 客户端
├── contracts.ts     # 前端使用的稳定契约
└── App.tsx          # 单页面 Chatbot 入口
```

| 模块 | 职责 | 不负责 | 测试入口 |
|---|---|---|---|
| API | 请求边界、Schema 校验、错误映射 | 合规判断 | `backend/tests/test_health.py`，后续 `test_api_*.py` |
| Agent | 闭集意图、ReAct 检查范围/工具选择、RAG 条款模型判断 | SQL、覆盖确定性规则、无限循环 | `backend/tests/test_chat_agent.py` |
| Providers | 隔离 Mock、Qdrant、FastEmbed | 改写证据或结果 | `test_qdrant_knowledge.py`、`test_retrieval_contracts.py` |
| Rules | 对已验证事实作确定性比较 | 调模型、检索标准 | 后续 `test_rule_engine.py` |
| Services | 固定顺序编排评估 | 绕过前置条件 | `test_citations_and_reports.py` |
| Repositories | 参数化查询及 Snapshot/报告不可变保存 | Text-to-SQL | `test_snapshot_repository.py`、`test_citations_and_reports.py` |
| Frontend | 聊天和报告呈现 | 生成审计结论 | `frontend/src/contracts.test.ts` |

## 2. 核心接口/API

| 方法 | 路径 | 用途 | 状态 |
|---|---|---|---|
| GET | `/health` | 存活检查 | 已建立 |
| POST | `/api/v1/chat/messages` | 意图路由入口 | 已实现 |
| GET | `/api/v1/config/current` | 默认 Mock 配置摘要、Snapshot 哈希和 JSON Pointer 证据 | 已实现 |
| GET | `/api/v1/reports` | 结构化查询报告 | 已实现 |
| GET | `/api/v1/reports/{report_id}` | 读取不可变报告 | 已实现 |

报告只能由 Chat Agent 的 `create_report` 工具创建，不提供绕开 Agent 的检测或报告创建入口。代码内的核心可替换接口为 `ConfigProvider`、`KnowledgeRetriever` 和 `ReportRepository`；确定性规则引擎是报告生成阶段的内部能力。

## 3. 关键数据结构

- `FirewallSnapshot`：不可变 Mock 原文、来源、版本和 SHA-256。
- `StoredSnapshot`：Snapshot、标准化配置、完整度、警告和证据的 SQLite 原子持久化记录。
- `ConfigurationEvidence`：值、JSON Pointer、快照 ID 和验证状态。
- `KnowledgeChunk`：确定性 Qdrant point ID、来源指针、文本类型、审核状态和内容哈希。
- `ValidatedStandardReference`：标准引用状态；只有 `text_kind=verbatim`、`citation_eligible=true` 且满足审核门禁的数据可以携带原文。
- `AuditFinding`：稳定 ID、控制/规则 ID、四态结果和两类证据。
- `AuditReport`：快照、目录、规则版本、Finding 及报告哈希。
- `ReportFilter`：后端白名单字段；模型只生成该结构，不生成 SQL。

## 4. 主链路

```text
用户消息
→ 限流/长度检查
→ 意图与结构化参数
→ ReAct 模型从当前允许工具中选择 Action
→ 后端校验白名单、依赖关系、调用次数和参数
→ 执行工具并返回脱敏 Observation
→ 获取并解析默认 Mock CLI
→ RAG 召回审核标准候选
→ 模型对未被确定性规则覆盖的原文条款形成四态判断
→ 校验 record_id、条款原文、配置字段和 ConfigurationVerified 证据
→ 执行 12 条高置信度确定性控制项
→ 按二级、三级、四级分别检查适用性
→ 绑定 ConfigurationVerified 证据
→ Qdrant 精确取回并校验标准依据
→ 12 个确定性规则优先判断，与证据门控后的模型辅助 Finding 去重合并
→ 事务保存不可变 Report
→ 页面查询和解释同一 Report
```

任何引用、规则或保存失败均失败关闭；不可引用摘要只允许形成 `Incomplete` 报告。

当前 Finding 使用 `Passed`、`Failed`、`NeedsReview` 和 `NotApplicable` 四态。确定性规则结果优先；其他原文条款由模型判断并标记为 `MODEL-ASSISTED-RAG`。缺少 `ConfigurationVerified` 证据时强制为 `NeedsReview`。当前分级结果只表示单台防火墙配置的匹配状态，不生成报告级总体合规结论。

## 5. 权限、隔离和系统边界

- 浏览器只访问 FastAPI；DeepSeek、Qdrant、SQLite 和文件系统均不直接暴露给前端。
- 模型没有 SQL、Shell、任意 HTTP、文件路径或知识库 ID 控制权。
- 配置查询展示默认 Mock 的厂商 CLI 风格原始文本；原始 CLI 不发送公网模型。检测说明只允许使用内置 Mock 的标准化 JSON 和确定性报告。
- Completed Report 和 Finding 不提供更新接口。
- 当前版本是无登录的本地单用户演示，不提供公网、多用户或不可信网络访问能力。
- `.env`、SQLite、密钥和生成物由 Git 忽略；仓库只提交 `.env.example`。

## 6. 待确认/冲突边界

1. **置信度分层**：440 条审核知识可进入 RAG 模型辅助检测，但其中只有 12 个已编码检查点属于高置信度确定性结论；其他结果必须显示模型辅助限制。
2. **DeepSeek账号验证**：模型代码和结构化输出回退已实现，仍需使用实际 API Key 完成账号级冒烟验证；无 Key 时回退到本地意图路由和确定性基线报告。
3. **结果口径**：规则结果是配置匹配初步结果，`control_conclusion_allowed=false`，不是最终等级保护结论。
