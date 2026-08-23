# Bank Firewall Compliance Chatbot

两天面试场景代码题的可信 MVP：一个 React 单页面 Chatbot，由 FastAPI 运行最多 6 步的受控 ReAct Agent。Agent 根据已解析的 Mock 配置选择检查范围，调用 Qdrant Local RAG 召回审核标准；12 条确定性规则优先生成高置信度结论，其他条款由 DeepSeek 判断并经配置证据门控后合并进带 SHA-256 的不可变 SQLite 报告。

当前实现不是生产系统，也不是最终等级保护测评结论。它没有登录，只允许绑定本机回环地址演示；不连接真实设备、不上传配置、不调用模型修改配置。

## 已实现

- 自然语言查询配置、运行检测、列历史报告、筛选结构化结果和解释 Finding；
- 检测主链路使用 `Reason → Action → Observation` 的有限步 ReAct 循环，工具严格白名单且不允许自由无限调用；
- ReAct 工具为 `get_current_config`、`retrieve_standards`、`evaluate_compliance_candidates`、`create_report`和 `finish`；
- 检测报告按二/三/四级折叠展示动态数量的 Finding：12 条确定性规则按等级展开为基线，RAG 模型辅助条款去重后增量合并；
- 受控会话上下文：保存上一轮消息、意图和查询对象，支持配置查询后的格式追问，不保存完整历史或工具载荷；
- 对话输入上限 16000 字符；可粘贴项目内置 Mock CLI 触发固定检测，其他 CLI 在本地拒绝，不发送给 DeepSeek；
- 默认 Huawei Mock CLI → 确定性 CLI 解析器 → 标准化 JSON → 不可变 Snapshot → JSON Pointer 证据；
- `POST /api/v1/config/parse` 可单独验证 Huawei CLI 片段的结构化解析结果；
- 二级、三级、四级分别执行 12 条确定性规则；
- 440 条人工审核记录、688 段可引用标准原文的 Qdrant Local 索引；
- 千问 `text-embedding-v4`（未配置时回退本地 BGE）+ 本地 BM25 双路召回；
- Qdrant RRF 融合候选，再由千问 `qwen3-rerank` 二次排序；Rerank 失败时回退 RRF；
- Citation Validator：拒绝摘要冒充标准原文，检测载荷篡改；
- 不可变 Report JSON、报告 SHA-256、SQLite 更新/删除拒绝；
- 提示词注入前置阻断和闭集工具路由；
- DeepSeek V4 Pro 负责结构化意图、ReAct 范围/工具选择、未被确定性规则覆盖的 RAG 条款判断和检测说明；无 Key 时安全回退到只生成确定性基线报告；
- 后端、前端和 GitHub Actions 自动检查。

当前 440 条原文记录已经人工审核通过，发布为 688 个逐条款/逐测评单元的原文块，全部为 `text_kind=verbatim`、`citation_eligible=true`和 `review_status=HumanReviewed`。新生成的报告在所有适用引用通过哈希、等级和页码校验时显示 `Completed`。历史报告保持不可变，不会被回写。

## 1. 环境准备

建议使用 Python 3.12、Node.js 20+ 和 pnpm。

```bash
cp .env.example .env

cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

`.env`、SQLite、Qdrant 数据、模型缓存和前端构建目录都已被 Git 忽略。

DeepSeek 配置位置是项目根目录的 `.env`：

```text
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_API_KEY=在这里填写你的Key
DEEPSEEK_MODEL=deepseek-v4-pro
DEEPSEEK_TIMEOUT_SECONDS=45
```

不要把 Key 写入 `.env.example`、源码或 README。Key 为空时系统不会调用公网，自动使用确定性意图路由。

千问检索配置也位于项目根目录 `.env`：

```text
BAILIAN_EMBEDDING_BASE_URL=https://你的业务空间域名/compatible-mode/v1
BAILIAN_EMBEDDING_API_KEY=在这里填写Embedding Key
BAILIAN_EMBEDDING_MODEL=text-embedding-v4
BAILIAN_EMBEDDING_DIMENSION=1024

BAILIAN_RERANK_BASE_URL=https://你的业务空间域名/compatible-api/v1
BAILIAN_RERANK_API_KEY=在这里填写Rerank Key
BAILIAN_RERANK_MODEL=qwen3-rerank
```

两个 Base URL 需要使用百炼控制台给出的实际地域和业务空间地址。代码分别调用
`/embeddings` 和 `/reranks`，因此 Base URL 不要再包含这两个末级路径。只配置
Embedding 时会执行“BM25 + 千问向量 → RRF”；同时配置 Rerank 后执行
“BM25 + 千问向量 → RRF → qwen3-rerank”。

默认配置 `RAG_ENFORCE_REVIEW_STATUS=true`，只有审核状态为 `HumanReviewed` 的原文才会通过引用门禁。四态报告使用 `backend/data/app-v2.db`，旧报告不会被覆盖。

## 2. 构建本地标准索引

配置千问 Embedding 后，首次运行会调用 API 为 688 段审核原文生成向量；未配置时才会
下载约 100MB 的本地中文嵌入模型。索引写入 `backend/data/qdrant`：

```bash
cd backend
.venv/bin/python -m scripts.index_knowledge
```

预期输出包含：

```text
indexed 688 records
catalog_sha256=...
citation_eligible=688
```

切换 Embedding 模型或维度后必须重新运行索引命令。索引清单会绑定模型名称，旧集合
不会被新模型静默复用。

重新从四份经审查 Word 文档生成原文审核候选：

```bash
cd backend
.venv/bin/python -m scripts.extract_verbatim_candidates \
  --docx-root "/absolute/path/to/标准文档/核心标准"
```

机器候选见 `backend/data/catalog/verbatim-extraction-candidates-v1.json`，人工审核工作簿为
`outputs/verbatim-extraction/standard-verbatim-review-v1.xlsx`。该命令不会自动把候选标记为可引用原文。

审核完成后，校验 Excel 中的审核决定、原文和哈希，并发布可引用目录：

```bash
cd backend
.venv/bin/python -m scripts.publish_reviewed_verbatim
.venv/bin/python -m scripts.index_knowledge
```

发布结果为 `backend/data/catalog/reviewed-verbatim-catalog-v1.json`。存在 Pending、未填原因的 Rejected、重复 ID、原文变更或哈希不一致时，发布脚本会失败关闭。

检索冒烟测试：

```bash
.venv/bin/python -m scripts.search_knowledge \
  "防火墙远程日志和审计留存要求" --limit 5
```

## 3. 启动

后端：

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

前端：

```bash
cd frontend
pnpm install
pnpm dev
```

打开 `http://127.0.0.1:5173`。健康检查为 `http://127.0.0.1:8000/health`。

## 4. 推荐演示

依次发送：

1. `开始检测当前防火墙配置`
2. `列出所有不符合项`
3. 点击任意 Finding 的“询问判断依据与限制”
4. `查询远程日志和审计留存相关标准`
5. `查看历史报告`
6. 点击任意历史报告的“查看详情”，展开一个等级分组，再输入 `有哪些不符合`

新生成的报告应显示 `Completed`，Finding 的标准依据会展示审核通过的原文。如索引版本不一致、条款缺失或引用元数据错误，报告仍会失败关闭为 `Incomplete`。

## 5. API

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/health` | 存活检查 |
| POST | `/api/v1/chat/messages` | 受控 Chat Agent 入口 |
| GET | `/api/v1/config/current` | 当前 Mock Snapshot |
| POST | `/api/v1/config/parse` | Huawei CLI 片段转结构化 JSON 补丁 |
| GET | `/api/v1/reports` | 结构化查询报告 |
| GET | `/api/v1/reports/{report_id}` | 读取不可变报告 |

报告只能由受控 Chat Agent 检测链路创建，不能通过旁路 API 绕过 ReAct、RAG 和证据门控。报告筛选不接收 SQL；用户文本只会变成枚举意图和白名单过滤字段，仓储代码负责固定参数化查询。

## 6. 测试

```bash
cd backend
.venv/bin/pytest -q tests
```

```bash
cd frontend
pnpm test
pnpm typecheck
pnpm build
```

单元测试使用确定性嵌入器，不访问公网或下载模型。真实 Qdrant 冒烟测试使用上面的两个脚本。

## 7. 安全和审计边界

- 确定性规则覆盖范围内的 Passed/Failed 始终由本地规则产生且优先；规则未覆盖的 RAG 条款可由 DeepSeek 判断并进入报告，但明确标记为 `MODEL-ASSISTED-RAG`，不属于高置信度确定性结论；
- 配置查询只把用户问题交给 DeepSeek 做意图分类，不发送配置内容；命中后直接返回 [default-firewall.cfg](backend/data/mock/default-firewall.cfg) 的厂商 CLI 风格原始 Mock 文本，不向前端返回内部处理后的 JSON。检测说明才会把 Mock 标准化配置和固定规则报告 JSON 发送给 DeepSeek；
- 模型判断引用的所有配置字段必须存在 `ConfigurationVerified` 证据；否则 Passed/Failed/NotApplicable 强制门控为 NeedsReview；
- 配置字段缺失时证据状态为 `InsufficientEvidence`，Finding 统一进入 `NeedsReview`；
- Qdrant 的 BM25/向量召回、RRF 和千问 Rerank 决定模型辅助检查的候选范围，不得覆盖确定性规则结果；
- 只有 `text_kind=verbatim`、`citation_eligible=true` 且 `review_status=HumanReviewed` 的数据可以输出为标准原文；
- 报告绑定 snapshot、catalog、rule pack 和 report hash；
- Snapshot 和 Report 在 SQLite 中拒绝更新和删除；
- 没有真实配置、IP、密码、Token 或私钥进入默认 Mock；
- 当前版本无鉴权，禁止直接部署到公网。

系统骨架与模块测试入口见 [docs/system-skeleton.md](docs/system-skeleton.md)。
