# 系统骨架

## 1. 模块与目录

```text
agent-compose.yml                 # 双 Agent、Prompt、沙箱和模型环境

backend/app/
├── api/                          # HTTP 路由、共享依赖和受控工具网关
├── core/                         # 配置和错误码
├── models/                       # 配置、Run、Finding、RAG 和报告契约
├── parsers/                      # VendorDetector、ParserRegistry、Huawei Parser
├── providers/                    # Agent-Compose、Mock 配置、Qdrant、Embedding、Rerank
├── repositories/                 # SQLite 采集、快照、Session 和报告持久化
├── rules/                        # 12 个确定性控制项
└── services/                     # 配置管道、Agent 工具、检测和报告固化

frontend/src/
├── api/                          # FastAPI 客户端
├── stores/                       # Pinia 会话、Run 和报告状态
├── views/                        # 对话与合规报告页面
├── contracts.ts                 # 前端稳定契约
├── router.ts                    # Vue Router
└── App.vue                      # Vue 应用入口
```

| 模块 | 职责 | 不负责 | 测试入口 |
|---|---|---|---|
| Agent-Compose | 隔离运行双 Agent、记录 Run、约束结构化输出 | 配置解析、直接写报告 | `test_agent_compose_runtime.py` |
| API/BFF | Schema 校验、错误映射、Run 查询和最终固化入口 | 自行生成合规结论 | `test_health.py`、`test_agent_tool_workflow.py` |
| Agent Tools | 强制工具顺序、返回最小必要数据 | 绕过 Session 或任意工具调用 | `test_agent_tool_workflow.py` |
| Parsers | 识别厂商、选择产品 Parser、绑定原始行证据 | 调模型、判断标准条款 | `test_v2_configuration_pipeline.py` |
| Providers | 隔离 Mock API、Qdrant、模型和 Agent-Compose 协议 | 改写证据或报告 | `test_qdrant_knowledge.py`、`test_agent_compose_runtime.py` |
| Rules | 对已验证配置事实执行 12 个控制项 | 调模型、覆盖证据门禁 | `test_p0_assessment.py` |
| Services | 配置管道、检测会话和报告固化 | 绕过前置步骤 | `test_agent_tool_workflow.py`、`test_citations_and_reports.py` |
| Repositories | 参数化查询及不可变数据保存 | Text-to-SQL | `test_snapshot_repository.py`、`test_v2_configuration_pipeline.py` |
| Frontend | 对话、轮询、报告筛选和证据呈现 | 生成或修改合规结论 | `frontend/src/*.test.ts` |

## 2. 核心接口/API

| 方法 | 路径 | 用途 | 状态 |
|---|---|---|---|
| `GET` | `/health` | 存活检查 | 已实现 |
| `POST` | `/api/v1/conversations/messages` | 启动 Conversation Agent | 已实现 |
| `GET` | `/api/v1/conversation-runs/{run_id}` | 查询对话 Run | 已实现 |
| `POST` | `/api/v1/assessments` | 启动 Compliance Agent，不接收等保级别 | 已实现 |
| `GET` | `/api/v1/runs/{run_id}` | 查询检测 Run 并在成功后固化报告 | 已实现 |
| `GET` | `/api/v1/config/current` | 获取、识别并解析当前 Mock 配置 | 已实现 |
| `GET` | `/api/v1/compliance-reports` | 查询 v2 报告 | 已实现 |
| `GET` | `/api/v1/compliance-reports/latest` | 读取最新 v2 报告 | 已实现 |
| `GET` | `/api/v1/compliance-reports/{report_id}` | 读取 v2 报告详情 | 已实现 |
| `POST` | `/api/v1/agent-tools/*` | Agent-Compose 沙箱的受控工具网关 | 已实现、令牌保护 |

浏览器使用 Conversation Agent 入口；报告只能由成功的 Compliance Agent Run 固化，不提供公开创建接口。

## 3. 核心数据结构

- `RawConfigurationSnapshot`：配置 API 原始采集、来源、格式、厂商提示和 SHA-256。
- `FirewallSnapshot`：规范化前的不可变配置快照，绑定原始内容和识别厂商。
- `CurrentConfigResponse`：结构化配置、Parser 版本、完整度、警告和配置证据。
- `ConfigurationEvidence`：字段值、JSON Pointer、原始行号、摘录、Parser 和验证状态。
- `AssessmentSession`：Assessment 与 Agent Run 的绑定、已执行步骤、草稿和最终报告 ID。
- `KnowledgeChunk`：Qdrant point、标准来源、文本类型、审核状态和内容哈希。
- `ControlAssessmentDraft`：规则生成的 12 个控制项草稿，只能由受控工具准备。
- `ComplianceReport`：Agent Run、配置哈希、Finding、标准来源和报告哈希组成的不可变 v2 报告。

## 4. 主链路

```text
用户消息
→ FastAPI 启动 Conversation Agent Run
→ Conversation Agent 判断意图并调用白名单 API
→ 若为检测，创建 Assessment Session
→ FastAPI 启动 Compliance Agent Run
→ configuration.fetch：Mock API 获取原始 CLI并保存采集记录
→ vendor.detect：多特征厂商识别
→ configuration.parse：ParserRegistry 选择 Huawei Parser并保存快照
→ rules.evaluate：执行 12 个确定性控制项
→ standards.search：Dense + BM25 + RRF + Rerank 检索审核条款
→ report.prepare：标记草稿步骤完成
→ Agent 返回符合 JSON Schema 的 assessmentId/prepared/summary
→ FastAPI 检查 Run 成功、业务 ID 和步骤完整性
→ 校验标准原文、版本、哈希和配置证据
→ 固化不可变 Compliance Report v2
→ Vue 页面读取并按四态展示同一报告
```

工具调用顺序由服务端 Session 状态机强制执行。Agent 负责意图、流程编排和标准检索语句；配置事实、规则结果、引用文本和报告持久化不能由 Agent 自行构造。

## 5. 权限、隔离和系统边界

- 浏览器只访问 FastAPI，不直接访问 Agent-Compose daemon、Qdrant、SQLite 或模型 API。
- Compliance Agent 只能通过携带 `X-Agent-Tool-Token` 的白名单工具访问业务能力。
- 工具网关只返回必要摘要，原始 CLI 不进入 Compliance Agent 的模型上下文。
- Conversation Agent 读取配置时会看到当前 Mock API 返回的配置；真实数据接入前必须增加脱敏和授权。
- Agent 不能执行数据库查询、修改配置或直接写最终报告。
- 未完成全部工具步骤、Run 输出不符合 Schema 或业务 ID 不一致时，不生成完整报告。
- 标准引用只有通过原文、审核状态、版本和哈希校验后才可进入报告。
- `.env`、SQLite、Qdrant、模型缓存和构建产物由 Git 忽略。

## 6. 当前边界

1. **数据来源**：配置 Provider 已保留 API 边界，但本期只返回内置 Huawei Mock CLI。
2. **厂商支持**：当前只注册 Huawei Parser；未知厂商失败关闭。
3. **检测范围**：12 个控制项统一执行，不以等保级别作为扫描入口；适用等级只作为 Finding 元数据。
4. **Agent 边界**：正式检测必须经过 Agent-Compose；Agent 不覆盖确定性规则，也不直接固化报告。
5. **生产能力**：未实现真实配置脱敏、登录、RBAC、多租户、限流、TLS 终止和公网部署防护。
