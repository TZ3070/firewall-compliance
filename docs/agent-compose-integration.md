# Agent-Compose 接入边界

本项目把 Agent-Compose 作为 Agent 控制面和隔离运行时，而不是 Python 工具库。浏览器只访问 FastAPI；FastAPI 调用 Agent-Compose daemon 的 v2 ConnectRPC；Agent 沙箱只访问受控工具网关。

## 两个 Agent

- `conversation-orchestrator`：处理每一次自然语言输入，判断是启动检测、读取任务、读取报告还是读取配置，并通过 API 执行。
- `firewall-compliance-agent`：执行配置获取、厂商识别、产品解析、规则评估、混合 RAG 和报告准备。

两个 Agent 均使用 Agent-Compose 的 `codex` runner，并由 Agent-Compose 的 LLM
facade 将 runner 使用的 Responses 协议桥接到 DeepSeek 上游的 OpenAI 兼容
`chat_completions` 协议。模型由 `${DEEPSEEK_MODEL}` 选择。这里不使用 `dsh`
runner，因为当前版本的 `dsh` 不支持本项目用于固化 Agent 输出的
`outputSchemaJson`。真实 API Key 只从未提交的 `.env` 注入，并标记为 secret。

定义位于根目录 `agent-compose.yml`。

## 信任边界

1. Agent-Compose daemon 不直接暴露给浏览器。
2. 合规工具使用 `X-Agent-Tool-Token`，值由 `.env` 注入沙箱；日志和响应不得返回该值。
3. 原始 CLI 保存在不可变采集记录中，Agent 工具只返回必要摘要，避免把整份配置放进模型上下文。
4. Agent 不能直接写最终报告；后端检查 Run 成功、`assessmentId`、必需工具步骤、配置 SHA 和标准引用后固化。
5. Agent-Compose、RAG 或引用验证失败时显式返回失败或 `Incomplete`，不生成伪造的完整报告。

## Agent-Compose 控制面

FastAPI 使用以下官方 v2 procedure：

```text
POST /agentcompose.v2.RunService/StartAgentRun
POST /agentcompose.v2.RunService/GetRun
```

请求携带 `clientRequestId` 实现幂等，`payloadJson` 传递业务身份，`outputSchemaJson` 约束结构化输出。Agent-Compose 运行 ID会写入最终报告的 `agent_run_id`。

## 工具顺序

```text
configuration.fetch
vendor.detect
configuration.parse
rules.evaluate
standards.search
report.prepare
```

服务端状态机会拒绝越序调用。`standards.search` 使用现有 Dense + BM25 + RRF 混合检索；语义召回只用于找条款，不能替代配置规则和引用校验。

## 生产化待办

- 将 Mock Provider 替换为客户侧只读 API 适配器；
- Agent 工具网关启用 mTLS 或服务网格身份；
- Agent-Compose daemon 与 FastAPI 使用 HTTPS/内网连接；
- Run 状态查询改为事件流或 webhook；
- 增加 H3C/Cisco 等 VendorDetector 特征和 Parser；
- 对 Agent prompt、工具结果和报告固化建立完整审计日志。
