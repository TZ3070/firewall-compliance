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
  raw_config_excerpt?: string | null
  raw_line_start?: number | null
  raw_line_end?: number | null
  raw_config_sha256?: string | null
}

export interface AssessmentClauseReference {
  record_id?: string | null
  standard_code: string
  clause_id: string
  classified_protection_level: number
  printed_pages: number[]
  pdf_page_indexes: number[]
}

export interface LevelAssessmentFinding {
  finding_id: string
  classified_protection_level: number
  control_id: string
  control_title: string
  check_title: string
  rule_id: string
  result: FindingResult
  severity: string
  explanation: string
  standard_references: AssessmentClauseReference[]
  configuration_evidence: ConfigurationEvidence[]
  limitations: string[]
  control_coverage: 'full' | 'partial'
  control_conclusion_allowed: false
}

export type CitationValidationStatus =
  | 'Valid'
  | 'Missing'
  | 'NotCitable'
  | 'PayloadMismatch'
  | 'RetrieverUnavailable'

export interface ValidatedStandardReference extends AssessmentClauseReference {
  validation_status: CitationValidationStatus
  validation_message: string
  record_id: string | null
  point_id: string | null
  source_catalog_id: string | null
  source_record_pointer: string | null
  content_sha256: string | null
  text_kind: 'summary' | 'measurement' | 'verbatim' | null
  standard_text: string | null
}

export interface AuditFinding
  extends Omit<LevelAssessmentFinding, 'standard_references'> {
  standard_references: ValidatedStandardReference[]
}

export interface AuditLevelSummary {
  classified_protection_level: 2 | 3 | 4
  counts: Record<FindingResult, number>
  findings: AuditFinding[]
}

export interface AuditReport {
  schema_version: '1.0.0'
  report_id: string
  assessment_id: string
  snapshot_id: string
  target_id: string
  status: 'Completed' | 'Incomplete' | 'Failed'
  created_at: string
  rule_pack_version: string
  rule_pack_sha256: string
  control_catalog_id: string
  control_catalog_version: string
  control_catalog_sha256: string
  knowledge_catalog_id: string
  knowledge_catalog_version: string
  knowledge_catalog_sha256: string
  standard_sources: Array<{
    standard_code: string
    title: string
    file_name: string
    file_size_bytes: number
    pdf_sha256: string
  }>
  levels: AuditLevelSummary[]
  disclaimer: string
  report_sha256: string
}

export interface CurrentConfigResponse {
  snapshot_id: string
  target_id: string
  content_sha256: string
  original_config_format: 'vendor_cli_mock'
  original_config_content: string
  original_config_sha256: string
  completeness: number
  configuration: {
    target: {
      display_name: string
      vendor: string
      model: string
      software_version: string
    }
  }
}

export interface ChatConfigurationView {
  snapshot_id: string
  target_id: string
  display_name: string
  vendor: string
  model: string
  software_version: string
  snapshot_sha256: string
  output_format: 'original_cli' | 'structured_json'
  original_config_format: 'vendor_cli_mock' | null
  original_config_content: string | null
  original_config_sha256: string | null
  structured_configuration: Record<string, unknown> | null
}

export interface ReportSummary {
  report_id: string
  snapshot_id: string
  target_id: string
  status: string
  created_at: string
  counts: Record<FindingResult, number>
}

export interface KnowledgeResultView {
  record_id: string
  standard_code: string
  clause_ids: string[]
  title: string
  content: string
  text_kind: 'summary' | 'measurement' | 'verbatim'
  citation_eligible: boolean
  score: number
  retrieval_sources: Array<'exact' | 'dense' | 'sparse' | 'rrf' | 'rerank'>
}

export interface ReActObservation {
  step: number
  tool:
    | 'get_current_config'
    | 'retrieve_standards'
    | 'evaluate_compliance_candidates'
    | 'create_report'
    | 'finish'
  success: boolean
  summary: string
}

export interface AgentTrace {
  mode: 'bounded-react'
  max_steps: number
  observations: ReActObservation[]
  completed: boolean
  stop_reason: string
}

export interface AgentCandidateFinding {
  record_id: string
  standard_code: string
  clause_ids: string[]
  title: string
  model_suggestion: FindingResult
  gated_result: FindingResult
  configuration_fields: string[]
  evidence_gate: 'ConfigurationVerified' | 'InsufficientEvidence' | 'ModelOnly'
  explanation: string
  official_report_effect: 'EvidenceGated' | 'NeedsReview'
}

export interface ChatRequest {
  message: string
  conversation_id?: string
  active_report_id?: string
  finding_id?: string
}

export interface ChatResponse {
  conversation_id: string
  intent:
    | 'RunAssessment'
    | 'GetCurrentConfig'
    | 'ListReports'
    | 'FilterFindings'
    | 'ExplainFinding'
    | 'SearchStandards'
    | 'Help'
    | 'Unsupported'
  stage: 'Routing' | 'SafetyBlocked' | 'Completed' | 'Failed'
  content: string
  notices: string[]
  active_report_id: string | null
  report: AuditReport | null
  configuration: ChatConfigurationView | null
  report_summaries: ReportSummary[]
  findings: AuditFinding[]
  knowledge_results: KnowledgeResultView[]
  agent_trace: AgentTrace | null
  agent_candidate_findings: AgentCandidateFinding[]
  error_code: string | null
}
