<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'

import { findingResults, type ComplianceFinding, type FindingResult } from '../contracts'
import { useComplianceStore } from '../stores/compliance'

const store = useComplianceStore()
const input = ref('')
const messageScroll = ref<HTMLElement>()
const quickPrompts = [
  '开始检测当前防火墙配置',
  '读取最新的合规报告',
  '查看当前防火墙配置',
  '列出历史报告',
]

const resultLabels: Record<FindingResult, string> = {
  Passed: '符合',
  Failed: '不符合',
  NeedsReview: '待复核',
  NotApplicable: '不适用',
}
const resultOrder = findingResults
const statusText = computed(() => store.health ? `API ${store.health.version}` : 'API 未连接')

onMounted(() => store.initialize())
watch(() => store.messages.length, async () => {
  await nextTick()
  messageScroll.value?.scrollTo({ top: messageScroll.value.scrollHeight, behavior: 'smooth' })
})

function submit(text = input.value) {
  input.value = ''
  void store.submit(text)
}

function evidenceValue(value: unknown) {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2)
}

function findingKey(finding: ComplianceFinding) {
  return `${finding.finding_id}-${finding.rule_id}`
}
</script>

<template>
  <main class="app-shell">
    <section class="workspace-shell">
      <header class="app-header">
        <div class="brand-mark">盾</div>
        <div>
          <h1>银行防火墙合规检测</h1>
        </div>
        <el-tag :type="store.health ? 'success' : 'danger'" effect="dark">{{ statusText }}</el-tag>
      </header>

      <div class="workspace-body">
        <aside class="report-sidebar">
          <div class="sidebar-heading">
            <span>历史报告</span>
            <strong>{{ store.reports.length }}</strong>
          </div>
          <button
            v-for="report in store.reports"
            :key="report.report_id"
            class="report-link"
            :class="{ active: store.activeReport?.report_id === report.report_id }"
            type="button"
            @click="store.openReport(report.report_id)"
          >
            <span>{{ report.vendor === 'Huawei' ? '华为' : report.vendor }}防火墙合规检测报告</span>
            <small>{{ new Date(report.created_at).toLocaleString('zh-CN') }}</small>
            <em>{{ report.counts.Failed }} 不符合 · {{ report.counts.NeedsReview }} 复核</em>
          </button>
          <p v-if="store.reports.length === 0" class="empty-state">尚无 Agent-Compose 报告</p>
        </aside>

        <section class="chat-panel">
          <div ref="messageScroll" class="message-scroll" aria-live="polite">
            <article v-for="message in store.messages" :key="message.id" class="message" :class="message.role">
              <div class="avatar">{{ message.role === 'assistant' ? 'AI' : '你' }}</div>
              <div class="message-body">
                <p v-for="notice in message.notices" :key="notice" class="notice-banner">{{ notice }}</p>
                <p class="message-text">{{ message.text }}</p>

                <section v-if="message.configuration" class="payload-card">
                  <span class="card-label">原始配置快照</span>
                  <h2>{{ message.configuration.configuration.target.display_name }}</h2>
                  <div class="meta-grid">
                    <span>厂商：{{ message.configuration.vendor_detection.vendor }}</span>
                    <span>识别置信度：{{ message.configuration.vendor_detection.confidence }}</span>
                    <span>Parser：{{ message.configuration.parser_version }}</span>
                    <span>完整度：{{ message.configuration.completeness }}</span>
                  </div>
                  <code>CLI SHA-256 {{ message.configuration.original_config_sha256 }}</code>
                  <pre class="raw-config">{{ message.configuration.original_config_content }}</pre>
                </section>

                <section v-if="message.report" class="payload-card report-card">
                  <div class="report-heading">
                    <div>
                      <span class="card-label">
                        {{ message.reportFilter ? `${resultLabels[message.reportFilter]}条目筛选视图` : '不可变合规报告' }}
                        · {{ message.report.agent_runtime }}
                      </span>
                      <h2>{{ message.report.target_id }}</h2>
                    </div>
                    <el-tag :type="message.report.status === 'Completed' ? 'success' : 'warning'">
                      {{ message.report.status }}
                    </el-tag>
                  </div>
                  <div class="count-grid">
                    <div v-for="result in resultOrder" :key="result">
                      <strong>{{ message.report.counts[result] }}</strong>
                      <span>{{ resultLabels[result] }}</span>
                    </div>
                  </div>
                  <details v-for="finding in message.report.findings" :key="findingKey(finding)" class="finding-card" :open="finding.result === 'Failed'">
                    <summary>
                      <span class="result-pill" :class="`result-${finding.result}`">{{ resultLabels[finding.result] }}</span>
                      <strong>{{ finding.check_title }}</strong>
                      <code>{{ finding.control_key }}</code>
                    </summary>
                    <p>{{ finding.explanation }}</p>
                    <div class="evidence-list">
                      <div v-for="evidence in finding.configuration_evidence" :key="`${finding.finding_id}-${evidence.field}`" class="evidence-item">
                        <code>{{ evidence.field }}</code>
                        <pre>{{ evidenceValue(evidence.value) }}</pre>
                        <small v-if="evidence.raw_line_start">配置第 {{ evidence.raw_line_start }} 行：{{ evidence.raw_config_excerpt }}</small>
                      </div>
                    </div>
                    <blockquote v-for="reference in finding.standard_references" :key="`${finding.finding_id}-${reference.clause_id}-${reference.classified_protection_level}`">
                      <strong>{{ reference.standard_code }} · {{ reference.clause_id }}</strong>
                      <p>{{ reference.standard_text || reference.validation_message }}</p>
                    </blockquote>
                  </details>
                  <div class="report-hashes">
                    <code>Run {{ message.report.agent_run_id }}</code>
                    <code>Report SHA {{ message.report.report_sha256 }}</code>
                  </div>
                  <p class="disclaimer">{{ message.report.disclaimer }}</p>
                </section>
              </div>
            </article>

            <article v-if="store.busy" class="message assistant">
              <div class="avatar">AI</div>
              <div class="message-body processing">
                <span class="pulse"></span>
                <strong>Agent 正在运行</strong>
              </div>
            </article>
          </div>

          <footer class="composer-area">
            <div class="quick-prompts">
              <el-button v-for="prompt in quickPrompts" :key="prompt" round size="small" :disabled="store.busy" @click="submit(prompt)">
                {{ prompt }}
              </el-button>
            </div>
            <form class="composer" @submit.prevent="submit()">
              <textarea v-model="input" rows="2" maxlength="4000" aria-label="对话输入" @keydown.enter.exact.prevent="submit()"></textarea>
              <el-button native-type="submit" type="primary" :disabled="store.busy || !input.trim()">发送</el-button>
            </form>
            <p>当前只支持 Mock API 获取的 Huawei 配置；系统不会修改防火墙。</p>
          </footer>
        </section>
      </div>
    </section>
  </main>
</template>
