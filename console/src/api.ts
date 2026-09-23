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

export type TargetType = 'WEBSITE' | 'API' | 'IP_CIDR' | 'SYNTHETIC'
export type TargetEnvironment =
  | 'PRODUCTION'
  | 'STAGING'
  | 'DEVELOPMENT'
  | 'INTERNAL'
  | 'SYNTHETIC'
  | 'SYNTHETIC_LAB'
  | 'SYNTHETIC_RANGE'

export type TargetEntry = {
  target_ref: string
  name: string
  type: string
  target_type: TargetType
  environment: string
  description: string
  supported_profile_ids: string[]
  // Onboarding metadata. Seeded synthetic targets and operator-onboarded company targets share this
  // shape so the console can distinguish and govern them without special-casing.
  synthetic: boolean
  status: string
  enabled: boolean
  origin_source?: string
  authorization_reference: string
  authorized_scope: string[]
  allowed_path_prefixes: string[]
  excluded_path_prefixes: string[]
  credential_reference: string | null
  last_assessment_at: string | null
}

// The typed create request the browser sends. It never carries scanner arguments or secret values —
// only a bounded scope and an opaque credential *reference*.
export type TargetCreate = {
  target_type: TargetType
  display_name: string
  environment: TargetEnvironment
  owner?: string | null
  authorization_reference: string
  authorization_attested: boolean
  description?: string | null
  origins?: string[]
  allowed_path_prefixes?: string[]
  excluded_path_prefixes?: string[]
  wildcard_subdomains?: string[]
  wildcard_authorized?: boolean
  openapi_url?: string | null
  credential_reference?: string | null
  addresses?: string[]
  cidr_authorized?: boolean
}

export type ScopePreview = {
  authorized_scope: string[]
  origins: string[]
  addresses: string[]
  wildcard_subdomains: string[]
  allowed_path_prefixes: string[]
  excluded_path_prefixes: string[]
  openapi_url: string | null
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
  targets: () =>
    getJSON<{ items: TargetEntry[]; custom_target_entry: boolean }>('/api/console/targets'),
  profiles: () => getJSON<{ items: AssessmentProfile[] }>('/api/console/profiles'),
  health: () => getJSON<Health>('/api/console/health'),
  // Onboarding an authorized company target. The controller normalizes, validates and persists it;
  // the browser only submits a typed, bounded scope.
  previewTarget: (body: TargetCreate) =>
    postJSON<ScopePreview>('/api/console/targets/preview', body as Record<string, unknown>),
  createTarget: (body: TargetCreate) =>
    postJSON<TargetEntry>('/api/console/targets', body as Record<string, unknown>),
  disableTarget: (ref: string) =>
    postJSON<TargetEntry>(`/api/console/targets/${encodeURIComponent(ref)}/disable`, {}),
  enableTarget: (ref: string) =>
    postJSON<TargetEntry>(`/api/console/targets/${encodeURIComponent(ref)}/enable`, {}),
  // Typed assessment creation. It references a stable inventory target id; the controller enforces
  // that target's stored scope and fails closed on anything outside it.
  startAssessment: (body: { target_id: string; profile_id: string }) =>
    postJSON<{ run_id: string; target_id: string; profile_id: string; status: string }>(
      '/api/console/assessments',
      body,
    ),
}
