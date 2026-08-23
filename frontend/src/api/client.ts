import type {
  AuditReport,
  ChatRequest,
  ChatResponse,
  HealthResponse,
} from '../contracts'

export async function getHealth(): Promise<HealthResponse> {
  const response = await fetch('/health')
  if (!response.ok) {
    throw new Error(`health request failed: ${response.status}`)
  }
  return response.json() as Promise<HealthResponse>
}

export async function getReport(reportId: string): Promise<AuditReport> {
  const encodedReportId = reportId.split('/').map(encodeURIComponent).join('/')
  const response = await fetch(`/api/v1/reports/${encodedReportId}`)
  if (!response.ok) {
    throw new Error(`report request failed: ${response.status}`)
  }
  return response.json() as Promise<AuditReport>
}

export async function sendChatMessage(request: ChatRequest): Promise<ChatResponse> {
  const response = await fetch('/api/v1/chat/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  })
  if (!response.ok) {
    throw new Error(`chat request failed: ${response.status}`)
  }
  return response.json() as Promise<ChatResponse>
}
