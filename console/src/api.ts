// Typed API client for the Aegis operator console. The browser only ever issues these typed
// controller requests; it never constructs scanner commands, target origins or credentials.

export type RunStatus = 'QUEUED' | 'RUNNING' | 'PASS' | 'FAIL' | 'REVIEW' | 'INCOMPLETE'

export type Run = {
  id: string
  status: RunStatus
  target_name: string
  scope: string
  planner: string
  mode: string
  model: string | null
  variant: string
  scenario: string
  created_at: string
  completed_at: string | null
  planner_contract_version: number
  execution_policy_version: number
  usage: { requests: number; model_calls: number; reserved_tokens: number; reported_tokens: number }
  budgets: { target_requests: number; model_calls: number; token_reservations: number }
  candidate_counts: { generated: number; validated: number; rejected: number }
  safety_rejections: number
  finding_count: number
  finding_ids: string[]
  retest_of: string | null
  linked_retests: string[]
  verification: string | null
  terminal_reason: string | null
  engine?: string
  adapter_version?: string | null
  tool_reported_count?: number
  verifier_confirmed_count?: number
}

export type TargetEntry = {
  target_ref: string
  name: string
  type: string
  environment: string
  description: string
  supported_profile_ids: string[]
}

export type ProfileCapability = {
  capability_id: string
  title: string
  activity: string
  request_budget: number
  concurrency_budget: number
  time_budget_ms: number
  requires_authentication: boolean
  state_changing_possible: boolean
  verified_severity: string
  required_approvals: string[]
}

export type AssessmentProfile = {
  profile_id: string
  display_name: string
  operator_summary: string
  how_it_runs: string
  advanced: boolean
  engine: string
  environment: string
  available: boolean
  unavailable_reason: string
  capabilities: ProfileCapability[]
  isolation_boundary: string
}

export type Finding = {
  id: string
  severity: string
  confidence: string
  status: string
  vulnerability_class: string
  owasp_mapping: string
  source_engine: string
  affected_operation: string
  principal_object_direction: string
  discovery_scan: string
  linked_retest: string | null
  evidence_completeness: string
  created_at: string
  updated_at: string
  title: string
  provenance: string
  ai_hypothesis: string
  controller_execution: string
  deterministic_evidence: string
  verifier_conclusion: string
  patched_retest: string
  final_state: string
}

export type EventRecord = {
  event_id: string
  sequence: number
  timestamp: string
  scan_id: string
  finding_id: string | null
  actor_type: 'OPERATOR' | 'AI_PLANNER' | 'CONTROLLER' | 'TOOL_RUNNER' | 'VERIFIER' | 'SYSTEM'
  event_type: string
  stage: string
  status: string
  engine: string
  summary: string
  evidence_refs: Record<string, unknown>[]
  redaction_status: string
  integrity: { algorithm: string; digest: string }
}

export type Evidence = {
  artifact_type: string
  artifact_id: string
  scan_id: string
  method: string
  normalized_route: string
  principal_profile_name: string
  object_reference: string
  response_status: number | null
  timestamp: string
  request_id: string
  evidence_hash: string
  control_probe_role: string
  provenance?: string
}

export type RunDetail = {
  run: Run
  events: EventRecord[]
  evidence: Evidence[]
  lifecycle?: unknown[]
}

export type Health = Record<string, unknown> | null

export type ConsoleConfig = {
  console_version: string
  operational_engines: string[]
  beast?: { enabled?: boolean }
  zap_active?: { enabled?: boolean }
}

const jsonHeaders = { Accept: 'application/json' }

export async function getJSON<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: jsonHeaders })
  if (!response.ok) throw new Error(`Request failed (${response.status})`)
  return response.json() as Promise<T>
}

export async function postJSON<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(path, {
    method: 'POST',
    headers: { ...jsonHeaders, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    const problem = (await response.json().catch(() => ({}))) as { detail?: string }
    throw new Error(problem.detail ?? `Request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

export const consoleApi = {
  config: () => getJSON<ConsoleConfig>('/api/console/config'),
  runs: () => getJSON<{ items: Run[]; count: number }>('/api/console/runs?limit=50'),
  run: (id: string) => getJSON<RunDetail>(`/api/console/runs/${encodeURIComponent(id)}`),
  findings: () => getJSON<{ items: Finding[] }>('/api/console/findings'),
  targets: () => getJSON<{ items: TargetEntry[] }>('/api/console/targets'),
  profiles: () => getJSON<{ items: AssessmentProfile[] }>('/api/console/profiles'),
  health: () => getJSON<Health>('/api/console/health'),
  // Starting an assessment creates a real typed controller job and returns its real run address.
  startAssessment: (body: { target: string; variant: string; capability?: string | null }) =>
    postJSON<Run>('/api/scans', body),
}
