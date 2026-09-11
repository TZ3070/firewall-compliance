import type {
  AssessmentRunView,
  ComplianceReport,
  ConversationRunView,
  ConversationStartResponse,
  CurrentConfigResponse,
  HealthResponse,
} from '../contracts'

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const body = await response.json().catch(() => null) as {
      detail?: { code?: string; message?: string }
    } | null
    const error = new Error(body?.detail?.message ?? `HTTP ${response.status}`)
    error.name = body?.detail?.code ?? 'API_ERROR'
    throw error
  }
  return response.json() as Promise<T>
}

export async function getHealth(): Promise<HealthResponse> {
  return parseResponse(await fetch('/health'))
}

export async function startConversation(
  message: string,
  conversationId?: string,
): Promise<ConversationStartResponse> {
  return parseResponse(await fetch('/api/v1/conversations/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, conversation_id: conversationId }),
  }))
}

export async function getConversationRun(runId: string): Promise<ConversationRunView> {
  return parseResponse(await fetch(`/api/v1/conversation-runs/${encodeURIComponent(runId)}`))
}

export async function getAssessmentRun(runId: string): Promise<AssessmentRunView> {
  return parseResponse(await fetch(`/api/v1/runs/${encodeURIComponent(runId)}`))
}

export async function getComplianceReport(reportId: string): Promise<ComplianceReport> {
  const encoded = reportId.split('/').map(encodeURIComponent).join('/')
  return parseResponse(await fetch(`/api/v1/compliance-reports/${encoded}`))
}

export async function listComplianceReports(): Promise<ComplianceReport[]> {
  return parseResponse(await fetch('/api/v1/compliance-reports'))
}

export async function getCurrentConfig(): Promise<CurrentConfigResponse> {
  return parseResponse(await fetch('/api/v1/config/current'))
}
