import { FormEvent, useEffect, useRef, useState } from 'react'

import { getHealth, getReport, sendChatMessage } from './api/client'
import type {
  AuditFinding,
  AuditReport,
  CitationValidationStatus,
  ChatResponse,
  FindingResult,
  HealthResponse,
  ReportSummary,
} from './contracts'

const evidenceStatusLabels = {
  ConfigurationVerified: '配置已验证',
  UserConfirmed: '用户已确认',
  ModelInferred: '模型推断（不作为确定性证据）',
  InsufficientEvidence: '证据不足',
} as const

const resultLabels: Record<FindingResult, string> = {
  Passed: '符合',
  Failed: '不符合',
  NeedsReview: '人工复核',
  NotApplicable: '不适用',
}

const citationStatusLabels: Record<CitationValidationStatus, string> = {
  Valid: '已校验原文',
  Missing: '未找到引用',
  NotCitable: '仅目录摘要，不可作为原文引用',
  PayloadMismatch: '引用内容校验失败',
  RetrieverUnavailable: '标准检索不可用',
}

const quickPrompts = [
  '开始检测当前防火墙配置',
  '列出所有不符合项',
  '查看历史报告',
  '查询远程日志和审计留存相关标准',
]

interface ChatMessage {
  id: string
  role: 'assistant' | 'user'
  text: string
  response?: ChatResponse
  report?: AuditReport
}

function messageId() {
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function withoutPhaseLabel(text: string) {
  return text.replace(/\bP0\b/gi, '当前规则集')
}

function formatEvidenceValue(value: unknown) {
  if (typeof value === 'string') return value
  if (value === undefined) return '未提供'
  return JSON.stringify(value, null, 2)
}

function FindingCard({
  finding,
  onExplain,
}: {
  finding: AuditFinding
  onExplain: (finding: AuditFinding) => void
}) {
  return (
    <article className="finding-card">
      <div className="finding-heading">
        <span className={`result-pill result-${finding.result}`}>
          {resultLabels[finding.result]}
        </span>
        <span className="severity">{finding.severity}</span>
        {finding.rule_id === 'MODEL-ASSISTED-RAG' && (
          <span className="severity">模型辅助·证据门控</span>
        )}
        <code>{finding.control_id}</code>
      </div>
      <h3>{finding.check_title}</h3>
      <p>{withoutPhaseLabel(finding.explanation)}</p>
      <section className="configuration-evidence">
        <strong>解析后的配置</strong>
        {finding.configuration_evidence.length > 0 ? (
          <div className="evidence-list">
            {finding.configuration_evidence.map((evidence) => (
              <div
                className="evidence-item"
                key={`${finding.finding_id}-${evidence.source_pointer}`}
              >
                <div className="evidence-heading">
                  <code>{evidence.field}</code>
                  <span>{evidenceStatusLabels[evidence.verification_status]}</span>
                </div>
                <pre>{formatEvidenceValue(evidence.value)}</pre>
                <small>来源指针：<code>{evidence.source_pointer}</code></small>
              </div>
            ))}
          </div>
        ) : (
          <p className="empty-evidence">未找到可用于本条判定的解析配置字段。</p>
        )}
      </section>
      <div className="reference-list">
        {finding.standard_references.map((reference) => (
          <div className="reference-item" key={`${finding.finding_id}-${reference.clause_id}`}>
            <span>
              {reference.standard_code} · {reference.clause_id}
              {reference.validation_status !== 'Valid' && (
                <> · <strong>{citationStatusLabels[reference.validation_status]}</strong></>
              )}
            </span>
            {reference.standard_text && (
              <pre className="standard-verbatim">{reference.standard_text}</pre>
            )}
          </div>
        ))}
      </div>
      <button className="text-button" onClick={() => onExplain(finding)} type="button">
        询问判断依据与限制
      </button>
    </article>
  )
}

function ResponsePayload({
  response,
  onExplain,
  onOpenReport,
  activeReportId,
  openingReportId,
  reportActionsDisabled,
}: {
  response: ChatResponse
  onExplain: (finding: AuditFinding) => void
  onOpenReport: (report: ReportSummary) => void
  activeReportId?: string
  openingReportId?: string
  reportActionsDisabled: boolean
}) {
  return (
    <>
      {response.report && (
        <ReportCard report={response.report} onExplain={onExplain} />
      )}

      {response.configuration && (
        <section className="payload-card">
          <span className="card-label">当前 Mock 配置快照</span>
          <h2>{response.configuration.display_name}</h2>
          <div className="config-grid">
            <span>厂商：{response.configuration.vendor}</span>
            <span>型号：{response.configuration.model}</span>
            <span>版本：{response.configuration.software_version}</span>
            <span>
              格式：{response.configuration.output_format === 'structured_json'
                ? '结构化 JSON'
                : '原始厂商 CLI Mock'}
            </span>
          </div>
          <code>Snapshot SHA {response.configuration.snapshot_sha256}</code>
          <div className="raw-config">
            <strong>
              {response.configuration.output_format === 'structured_json'
                ? '结构化配置 JSON'
                : '原始厂商配置'}
            </strong>
            <pre>
              {response.configuration.output_format === 'structured_json'
                ? JSON.stringify(response.configuration.structured_configuration, null, 2)
                : response.configuration.original_config_content}
            </pre>
          </div>
        </section>
      )}

      {response.report_summaries.length > 0 && (
        <section className="payload-list">
          {response.report_summaries.map((report) => (
            <article className="payload-card compact-card" key={report.report_id}>
              <div>
                <strong>{report.target_id}</strong>
                <span>{new Date(report.created_at).toLocaleString('zh-CN')}</span>
              </div>
              <span>{report.status}</span>
              <small>
                {report.counts.Failed} 不符合 · {report.counts.NeedsReview} 人工复核
              </small>
              <button
                className="report-detail-button"
                disabled={reportActionsDisabled || activeReportId === report.report_id}
                onClick={() => onOpenReport(report)}
                type="button"
              >
                {openingReportId === report.report_id
                  ? '正在加载…'
                  : activeReportId === report.report_id
                    ? '当前报告'
                    : '查看详情'}
              </button>
            </article>
          ))}
        </section>
      )}

      {response.findings.length > 0 && (
        <section className="finding-list">
          {response.findings.map((finding) => (
            <FindingCard finding={finding} key={finding.finding_id} onExplain={onExplain} />
          ))}
        </section>
      )}

      {response.knowledge_results.length > 0 && (
        <section className="knowledge-list">
          {response.knowledge_results.map((item) => (
            <article className="payload-card knowledge-card" key={item.record_id}>
              <div className="knowledge-heading">
                <span>{item.standard_code}</span>
                <span className={item.citation_eligible ? 'citable' : 'not-citable'}>
                  {item.citation_eligible ? '可引用原文' : '仅目录摘要'}
                </span>
              </div>
              <h3>{item.title}</h3>
              <small>{item.clause_ids.join(' · ') || '未标注条款号'}</small>
              <small>
                检索链路：{item.retrieval_sources.join(' → ')} · 得分 {item.score.toFixed(4)}
              </small>
              <p>{item.content}</p>
            </article>
          ))}
        </section>
      )}

    </>
  )
}

function ReportCard({
  report,
  onExplain,
}: {
  report: AuditReport
  onExplain: (finding: AuditFinding) => void
}) {
  const findingCount = report.levels.reduce(
    (total, level) => total + level.findings.length,
    0,
  )

  return (
    <section className="payload-card report-card">
      <div className="payload-title">
        <div>
          <span className="card-label">不可变检测报告</span>
          <h2>{report.target_id}</h2>
        </div>
        <span className={`report-status status-${report.status}`}>{report.status}</span>
      </div>
      <div className="level-grid">
        {report.levels.map((level) => (
          <div className="level-summary" key={level.classified_protection_level}>
            <strong>{level.classified_protection_level} 级</strong>
            <span>{level.counts.Passed} 符合</span>
            <span>{level.counts.Failed} 不符合</span>
            <span>{level.counts.NeedsReview} 人工复核</span>
            <span>{level.counts.NotApplicable} 不适用</span>
          </div>
        ))}
      </div>
      <div className="report-findings">
        <p className="report-findings-title">
          详细结果（{findingCount} 条 Finding）
        </p>
        {report.levels.map((level) => (
          <details className="report-level-details" key={level.classified_protection_level}>
            <summary>
              <strong>{level.classified_protection_level} 级 Finding</strong>
              <span>{level.findings.length} 条</span>
            </summary>
            <div className="finding-list">
              {level.findings.map((finding) => (
                <FindingCard
                  finding={finding}
                  key={finding.finding_id}
                  onExplain={onExplain}
                />
              ))}
            </div>
          </details>
        ))}
      </div>
      <div className="audit-meta">
        <code>Report SHA {report.report_sha256.slice(0, 16)}…</code>
        <code>Catalog SHA {report.knowledge_catalog_sha256.slice(0, 16)}…</code>
      </div>
      <details className="standard-sources">
        <summary>标准来源文件（{report.standard_sources.length}）</summary>
        {report.standard_sources.map((source) => (
          <div key={source.standard_code}>
            <span>{source.standard_code} · {source.file_name}</span>
            <code>SHA-256 {source.pdf_sha256}</code>
          </div>
        ))}
      </details>
      <p className="notice">{withoutPhaseLabel(report.disclaimer)}</p>
    </section>
  )
}

function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      text: '你好。我可以查询默认 Mock 防火墙配置、运行固定流程合规检测、筛选报告结果并检索本地标准目录。检测不会修改防火墙配置。',
    },
  ])
  const [input, setInput] = useState('')
  const [conversationId, setConversationId] = useState<string>()
  const [activeReportId, setActiveReportId] = useState<string>()
  const [openingReportId, setOpeningReportId] = useState<string>()
  const [loading, setLoading] = useState(false)
  const messageEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    getHealth().then(setHealth).catch(() => setHealth(null))
  }, [])

  useEffect(() => {
    messageEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  async function submitMessage(message: string, findingId?: string) {
    const trimmed = message.trim()
    if (!trimmed || loading || openingReportId) return

    setMessages((current) => [
      ...current,
      { id: messageId(), role: 'user', text: trimmed },
    ])
    setInput('')
    setLoading(true)
    try {
      const response = await sendChatMessage({
        message: trimmed,
        conversation_id: conversationId,
        active_report_id: activeReportId,
        finding_id: findingId,
      })
      setConversationId(response.conversation_id)
      if (response.active_report_id) setActiveReportId(response.active_report_id)
      setMessages((current) => [
        ...current,
        {
          id: messageId(),
          role: 'assistant',
          text: response.content,
          response,
        },
      ])
    } catch {
      setMessages((current) => [
        ...current,
        {
          id: messageId(),
          role: 'assistant',
          text: '请求失败。请确认 FastAPI 已启动，并已运行本地知识索引命令。',
        },
      ])
    } finally {
      setLoading(false)
    }
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    void submitMessage(input)
  }

  async function openHistoricalReport(summary: ReportSummary) {
    if (openingReportId) return

    setOpeningReportId(summary.report_id)
    try {
      const report = await getReport(summary.report_id)
      setActiveReportId(report.report_id)
      setMessages((current) => [
        ...current,
        {
          id: messageId(),
          role: 'assistant',
          text: `已打开历史报告，后续“有哪些不符合”等筛选将基于该报告。`,
          report,
        },
      ])
    } catch {
      setMessages((current) => [
        ...current,
        {
          id: messageId(),
          role: 'assistant',
          text: `无法加载历史报告 ${summary.report_id}。`,
        },
      ])
    } finally {
      setOpeningReportId(undefined)
    }
  }

  return (
    <main className="app-shell">
      <section className="chat-shell" aria-label="银行防火墙配置合规检测 Chatbot">
        <header className="chat-header">
          <div className="brand-mark" aria-hidden="true">盾</div>
          <div>
            <p className="eyebrow">LOCAL AUDIT AGENT</p>
            <h1>银行防火墙配置合规检测</h1>
            <p>受控 ReAct · 本地标准检索 · 不自动修改配置</p>
          </div>
          <span className={health ? 'service-status online' : 'service-status'}>
            {health ? `API ${health.version}` : 'API 未连接'}
          </span>
        </header>

        <div className="message-scroll" aria-live="polite">
          {messages.map((message) => (
            <article className={`message ${message.role}`} key={message.id}>
              <div className="avatar">{message.role === 'assistant' ? 'AI' : '你'}</div>
              <div className="message-body">
                {message.response && message.response.notices.length > 0 && (
                  <div className="degradation-notices" role="status">
                    {message.response.notices.map((notice) => (
                      <p key={notice}>{withoutPhaseLabel(notice)}</p>
                    ))}
                  </div>
                )}
                <p className="message-text">{withoutPhaseLabel(message.text)}</p>
                {message.response && (
                  <ResponsePayload
                    activeReportId={activeReportId}
                    openingReportId={openingReportId}
                    onOpenReport={(report) => void openHistoricalReport(report)}
                    reportActionsDisabled={loading || Boolean(openingReportId)}
                    response={message.response}
                    onExplain={(finding) =>
                      void submitMessage(
                        `解释 ${finding.check_title} 的判断依据和限制`,
                        finding.finding_id,
                      )
                    }
                  />
                )}
                {message.report && (
                  <ReportCard
                    report={message.report}
                    onExplain={(finding) =>
                      void submitMessage(
                        `解释 ${finding.check_title} 的判断依据和限制`,
                        finding.finding_id,
                      )
                    }
                  />
                )}
              </div>
            </article>
          ))}

          {loading && (
            <article className="message assistant">
              <div className="avatar">AI</div>
              <div className="message-body processing-card">
                <strong>正在处理…</strong>
              </div>
            </article>
          )}
          <div ref={messageEndRef} />
        </div>

        <footer className="composer-area">
          <div className="quick-prompts" aria-label="常用问题">
            {quickPrompts.map((prompt) => (
              <button disabled={loading || Boolean(openingReportId)} key={prompt} onClick={() => void submitMessage(prompt)} type="button">
                {prompt}
              </button>
            ))}
          </div>
          <form className="composer" onSubmit={handleSubmit}>
            <textarea
              aria-label="输入合规检测问题"
              maxLength={16000}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault()
                  event.currentTarget.form?.requestSubmit()
                }
              }}
              placeholder="例如：开始检测当前防火墙配置"
              rows={2}
              value={input}
            />
            <button disabled={loading || Boolean(openingReportId) || !input.trim()} type="submit">
              发送
            </button>
          </form>
          <p className="boundary-note">
            当前版本仅使用内置 Mock；标准摘要不可冒充原文；报告结果不是最终等保测评结论。
          </p>
        </footer>
      </section>
    </main>
  )
}

export default App
