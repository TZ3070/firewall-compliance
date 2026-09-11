export interface HealthResponse {
  status: 'ok'
  service: string
  version: string
}

export const findingResults = [
  'Passed',
  'Failed',
  'NeedsReview',
  'NotApplicable',
] as const

export type FindingResult = (typeof findingResults)[number]

export function isFindingResult(value: string): value is FindingResult {
  return findingResults.includes(value as FindingResult)
}

export type AgentRunStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'canceled'

export interface ConfigurationEvidence {
  snapshot_id: string
  field: string
  value: unknown
  source_pointer: string
  parser_version: string
  verification_status:
    | 'ConfigurationVerified'
    | 'UserConfirmed'
    | 'ModelInferred'
    | 'InsufficientEvidence'
  raw_config_excerpt: string | null
  raw_line_start: number | null
  raw_line_end: number | null
  raw_config_sha256: string | null
}

export interface ValidatedStandardReference {
  record_id: string | null
  standard_code: string
  clause_id: string
  classified_protection_level: number
  printed_pages: number[]
  pdf_page_indexes: number[]
  validation_status: 'Valid' | 'Missing' | 'NotCitable' | 'PayloadMismatch' | 'RetrieverUnavailable'
  validation_message: string
  standard_text: string | null
  content_sha256: string | null
}

export interface ComplianceFinding {
  finding_id: string
  control_key: string
  control_title: string
  check_title: string
  rule_id: string
  result: FindingResult
  severity: string
  explanation: string
  applicable_protection_levels: number[]
  standard_references: ValidatedStandardReference[]
  configuration_evidence: ConfigurationEvidence[]
  limitations: string[]
  coverage: 'full' | 'partial'
  origin: 'deterministic' | 'agent_assisted' | 'hybrid'
}

export interface ComplianceReport {
  schema_version: '2.0.0'
  report_id: string
  assessment_id: string
  snapshot_id: string
  snapshot_sha256: string
  original_config_sha256: string
  target_id: string
  vendor: string
  status: 'Completed' | 'Incomplete' | 'Failed'
  created_at: string
  agent_runtime: 'agent-compose'
  agent_run_id: string
  parser_version: string
  rule_pack_version: string
  counts: Record<FindingResult, number>
  findings: ComplianceFinding[]
  standard_sources: Array<{
    standard_code: string
    title: string
    file_name: string
    file_size_bytes: number
    pdf_sha256: string
  }>
  disclaimer: string
  report_sha256: string
}

export interface ConversationStartResponse {
  conversation_id: string
  run_id: string
  status: AgentRunStatus
  started: boolean
  status_url: string
}

export interface ConversationResult {
  intent: string
  message: string
  resourceId?: string | null
  resourceType?: 'assessment-run' | 'report' | 'configuration' | null
  findingFilter?: FindingResult | null
}

export interface ConversationRunView {
  run_id: string
  status: AgentRunStatus
  response: ConversationResult | null
  error_message: string | null
  warnings: string[]
}

export interface AssessmentRunView {
  assessment_id: string
  run_id: string
  status: AgentRunStatus
  report_id: string | null
  error_code: string | null
  error_message: string | null
  warnings: string[]
}

export interface CurrentConfigResponse {
  snapshot_id: string
  target_id: string
  parser_version: string
  original_config_content: string
  original_config_sha256: string
  completeness: number
  vendor_detection: {
    vendor: string
    confidence: number
    matched_signatures: string[]
  }
  configuration: {
    target: {
      display_name: string
      vendor: string
      product_family: string
      model: string
      software_version: string
    }
  }
}
