import { defineStore } from 'pinia'

import {
  getAssessmentRun,
  getComplianceReport,
  getConversationRun,
  getCurrentConfig,
  getHealth,
  listComplianceReports,
  startConversation,
} from '../api/client'
import type {
  ComplianceReport,
  CurrentConfigResponse,
  FindingResult,
  HealthResponse,
} from '../contracts'

interface Message {
  id: string
  role: 'assistant' | 'user'
  text: string
  report?: ComplianceReport
  reportFilter?: FindingResult
  configuration?: CurrentConfigResponse
  notices?: string[]
}

const terminal = new Set(['succeeded', 'failed', 'canceled'])

function id() {
  return crypto.randomUUID()
}

async function pause(milliseconds: number) {
  await new Promise((resolve) => window.setTimeout(resolve, milliseconds))
}

const findingNames: Record<FindingResult, string> = {
  Passed: '合规',
  Failed: '不合规',
  NeedsReview: '待复核',
  NotApplicable: '不适用',
}

function reportTitle(report: ComplianceReport) {
  const vendor = report.vendor.toLowerCase() === 'huawei' ? '华为' : report.vendor
  return `${vendor}防火墙合规检测报告`
}

function formatCreatedAt(value: string) {
  return new Date(value).toLocaleString('zh-CN')
}

function filterReport(report: ComplianceReport, findingFilter?: FindingResult | null) {
  if (!findingFilter) return report
  const findings = report.findings.filter((finding) => finding.result === findingFilter)
  return {
    ...report,
    counts: {
      Passed: findingFilter === 'Passed' ? findings.length : 0,
      Failed: findingFilter === 'Failed' ? findings.length : 0,
      NeedsReview: findingFilter === 'NeedsReview' ? findings.length : 0,
      NotApplicable: findingFilter === 'NotApplicable' ? findings.length : 0,
    },
    findings,
  }
}

export const useComplianceStore = defineStore('compliance', {
  state: () => ({
    health: null as HealthResponse | null,
    messages: [] as Message[],
    reports: [] as ComplianceReport[],
    activeReport: null as ComplianceReport | null,
    conversationId: undefined as string | undefined,
    busy: false,
  }),
  actions: {
    async initialize() {
      const [health, reports] = await Promise.allSettled([getHealth(), listComplianceReports()])
      this.health = health.status === 'fulfilled' ? health.value : null
      this.reports = reports.status === 'fulfilled' ? reports.value : []
    },
    async submit(message: string) {
      const text = message.trim()
      if (!text || this.busy) return
      this.messages.push({ id: id(), role: 'user', text })
      this.busy = true
      try {
        const started = await startConversation(text, this.conversationId)
        this.conversationId = started.conversation_id
        let run = await getConversationRun(started.run_id)
        for (let attempt = 0; !terminal.has(run.status) && attempt < 180; attempt += 1) {
          await pause(1000)
          run = await getConversationRun(started.run_id)
        }
        if (run.status !== 'succeeded' || !run.response) {
          throw new Error(run.error_message ?? '对话 Agent 未完成')
        }
        if (run.response.intent === 'ListReports') {
          await this.showReportHistory(run.warnings)
          return
        }
        const resolved = await this.resolveResource(
          run.response.resourceType,
          run.response.resourceId,
          run.response.findingFilter,
          run.response.message,
          run.warnings,
        )
        if (!resolved) {
          this.messages.push({
            id: id(),
            role: 'assistant',
            text: run.response.message,
            notices: run.warnings,
          })
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : '未知错误'
        this.messages.push({ id: id(), role: 'assistant', text: `请求未完成：${message}` })
      } finally {
        this.busy = false
      }
    },
    async showReportHistory(notices?: string[]) {
      this.reports = await listComplianceReports()
      const text = this.reports.length === 0
        ? '暂无历史报告。'
        : [
            `共 ${this.reports.length} 份历史报告：`,
            ...this.reports.map(
              (report, index) => `${index + 1}. ${reportTitle(report)} · ${formatCreatedAt(report.created_at)}`,
            ),
          ].join('\n')
      this.messages.push({ id: id(), role: 'assistant', text, notices })
    },
    async resolveResource(
      type?: string | null,
      resourceId?: string | null,
      findingFilter?: FindingResult | null,
      agentMessage?: string,
      notices?: string[],
    ) {
      if (type === 'assessment-run' && resourceId) {
        let run = await getAssessmentRun(resourceId)
        for (let attempt = 0; !terminal.has(run.status) && attempt < 300; attempt += 1) {
          await pause(1000)
          run = await getAssessmentRun(resourceId)
        }
        if (run.status !== 'succeeded' || !run.report_id) {
          throw new Error(run.error_message ?? '合规检测 Agent 未完成')
        }
        const report = await getComplianceReport(run.report_id)
        this.activeReport = report
        this.messages.push({
          id: id(),
          role: 'assistant',
          text: `检测完成：${report.counts.Passed} 项符合，${report.counts.Failed} 项不符合，${report.counts.NeedsReview} 项待复核。`,
          report,
          notices,
        })
        this.reports = await listComplianceReports()
        return true
      } else if (type === 'report' && resourceId) {
        const report = await getComplianceReport(resourceId)
        this.activeReport = report
        const visibleReport = filterReport(report, findingFilter)
        const text = findingFilter
          ? `共找到 ${visibleReport.findings.length} 项${findingNames[findingFilter]}条目。`
          : (agentMessage || '已加载最新合规报告。')
        this.messages.push({
          id: id(),
          role: 'assistant',
          text,
          report: visibleReport,
          reportFilter: findingFilter || undefined,
          notices,
        })
        return true
      } else if (type === 'configuration') {
        const configuration = await getCurrentConfig()
        this.messages.push({
          id: id(),
          role: 'assistant',
          text: agentMessage || `已读取 ${configuration.vendor_detection.vendor} 配置快照。`,
          configuration,
          notices,
        })
        return true
      }
      return false
    },
    async openReport(reportId: string) {
      this.activeReport = await getComplianceReport(reportId)
      this.messages.push({
        id: id(),
        role: 'assistant',
        text: `${reportTitle(this.activeReport)} · ${formatCreatedAt(this.activeReport.created_at)}`,
        report: this.activeReport,
      })
    },
  },
})
