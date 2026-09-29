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
  owner?: string | null
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
  origins?: string[]
  addresses?: string[]
  wildcard_subdomains?: string[]
  allowed_path_prefixes: string[]
  excluded_path_prefixes: string[]
  openapi_url?: string | null
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
  execution_mode?: 'STANDARD' | 'NETWORK_RUNNER'
  tools?: string[]
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
  zap_active?: { enabled?: boolean }
}

export type AiModelCatalog = {
  provider: string
  current_model: string
  models: string[]
  runtime_switching: boolean
}

export type AiBalance = {
  provider: string
  state: 'AVAILABLE' | 'UNAVAILABLE' | 'UNSUPPORTED'
  available: boolean | null
  balances: Array<{
    currency: 'USD' | 'CNY'
    remaining: string
    granted?: string
    topped_up?: string
  }>
  total_credits?: string
  total_usage?: string
  key_limit?: string | null
  limit_reset?: string | null
  code?: string
  checked_at: string
}

export type SyntheticAiTestResult = {
  test_id: string
  status: 'PASS' | 'FAIL'
  code: string
  provider: string
  model: string
  decision_type: string | null
  usage: { input_tokens: number; output_tokens: number; total_tokens: number }
  fixture_state: 'DESTROYED'
  cleanup_verified: boolean
  docker_resources_created: 0
  started_at: string
  completed_at: string
}

// BEAST disposable adversary sandbox (Phase 1.4 / 1.4-B). Deliberately gated: the browser can only
// preflight, type the exact confirmation phrase, request a lease + run, poll it, and emergency-stop.
// The controller owns target scope, the typed-phrase gate, the verifier and all cleanup.
export type BeastConfig = {
  enabled: boolean
  mode: string
  available_mode: string | null
  profile_id: string
  required_model: string
  synthetic_lab_only: boolean
  target_refs: string[]
  tools: BeastTool[]
  technical_subtitle: string
  boundary_description: string
}

export type BeastTool = {
  name: string
  category: string
  purpose: string
  source: string
}

export type ToolboxToolHealth = BeastTool & {
  status: 'READY' | 'MISSING' | 'ERROR' | 'UNAVAILABLE'
  detail: string
}

export type ToolboxHealth = {
  state: 'READY' | 'DEGRADED' | 'UNAVAILABLE'
  checked_at: string
  reason: string
  ready?: number
  total?: number
  tools: ToolboxToolHealth[]
}

export type BeastResourceEnvelope = {
  total_wall_time_seconds: number
  per_command_timeout_seconds: number
  max_commands: number
  max_request_rate_per_second: number
  max_target_connections: number
} & Record<string, number>

export type BeastTargetView = {
  target_ref: string
  name: string
  origin: string
  base_path: string
  environment: string
  allowed_methods: string[]
  allowed_path_prefix: string
  prohibited_operations: string[]
  synthetic_data_only: boolean
  health: string
  expected_impact: string
  max_blast_radius: string
}

export type BeastPreflight = {
  profile_id: string
  mode: string
  target: BeastTargetView
  enabled_capabilities: string[]
  enabled_engines: string[]
  resources: BeastResourceEnvelope
  automatic_expiry_seconds: number
  emergency_stop: string
  technical_subtitle: string
  boundary_description: string
}

export type BeastLease = {
  lease_id: string
  state: string
  target_ref: string
  profile_id: string
  capability_set: string[]
  expires_at: string
}

// The AI's authored command for one turn (exact text preserved; never rewritten by the controller).
export type BeastCommand = {
  command_id: string
  parent_command_id: string | null
  sequence: number
  command_text: string
  expected_intent: string
  hypothesis_reference: string
}

// The bounded, normalized result the AI sees back — never a raw credentialed response body.
export type BeastObservation = {
  observation_id: string
  command_id: string
  sequence: number
  summary: string
  command_text: string
  facts: Record<string, unknown>
  stdout: string
  stderr: string
  artifact_previews: Record<string, string>
}

// One model call: the structured decision plus provenance (tokens, timing, digest) for debugging.
export type BeastModelCall = {
  sequence: number
  model: string
  usage: Record<string, number>
  metadata: Record<string, unknown>
  decision_type: string
  input_observation_ids: string[]
}

export type BeastRunView = {
  run_id: string
  lease_id: string
  target_ref: string
  scenario_id: string
  state: string
  model: string
  stop_reason: string | null
  workspace_destroyed: boolean
  cleanup_verified: boolean
  emergency_stopped: boolean
  commands: BeastCommand[]
  observations: BeastObservation[]
  model_calls: BeastModelCall[]
  verifier_conclusion: Record<string, unknown> | null
  created_at: string
  completed_at: string | null
}

export type BeastEvent = {
  sequence: number
  event_id: string
  run_id: string
  event_type: string
  actor_type: string
  timestamp: string
  details: Record<string, unknown>
}

export type BeastRunDetail = { run: BeastRunView; events: BeastEvent[] }

const jsonHeaders = { Accept: 'application/json' }

export async function getJSON<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: jsonHeaders })
  if (!response.ok) {
    const problem = (await response.json().catch(() => ({}))) as { detail?: string }
    throw new Error(problem.detail ?? `Request failed (${response.status})`)
  }
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

export async function putJSON<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(path, {
    method: 'PUT',
    headers: { ...jsonHeaders, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) {
    const problem = (await response.json().catch(() => ({}))) as { detail?: string }
    throw new Error(problem.detail ?? `Request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

export async function deleteJSON(path: string): Promise<void> {
  const response = await fetch(path, { method: 'DELETE', headers: jsonHeaders })
  if (!response.ok) {
    const problem = (await response.json().catch(() => ({}))) as { detail?: string }
    throw new Error(problem.detail ?? `Request failed (${response.status})`)
  }
}

export const consoleApi = {
  config: () => getJSON<ConsoleConfig>('/api/console/config'),
  aiModels: () => getJSON<AiModelCatalog>('/api/console/ai/models'),
  aiBalance: () => getJSON<AiBalance>('/api/console/ai/balance'),
  selectAiModel: (model: string) =>
    postJSON<AiModelCatalog>('/api/console/ai/select', { model }),
  testAi: () => postJSON<SyntheticAiTestResult>('/api/console/ai/test', {}),
  runs: () => getJSON<{ items: Run[]; count: number }>('/api/console/runs?limit=50'),
  run: (id: string) => getJSON<RunDetail>(`/api/console/runs/${encodeURIComponent(id)}`),
  findings: () => getJSON<{ items: Finding[] }>('/api/console/findings'),
  targets: () =>
    getJSON<{ items: TargetEntry[]; custom_target_entry: boolean }>('/api/console/targets'),
  profiles: () => getJSON<{ items: AssessmentProfile[] }>('/api/console/profiles'),
  health: () => getJSON<Health>('/api/console/health'),
  toolboxHealth: () => getJSON<ToolboxHealth>('/api/console/toolbox/health'),
  // Onboarding an authorized company target. The controller normalizes, validates and persists it;
  // the browser only submits a typed, bounded scope.
  previewTarget: (body: TargetCreate) =>
    postJSON<ScopePreview>('/api/console/targets/preview', body as Record<string, unknown>),
  createTarget: (body: TargetCreate) =>
    postJSON<TargetEntry>('/api/console/targets', body as Record<string, unknown>),
  // Edit an operator-onboarded target's scope in place (synthetic/seeded targets are not editable
  // and the controller returns 404). Re-validated and re-normalized exactly like creation.
  updateTarget: (ref: string, body: TargetCreate) =>
    putJSON<TargetEntry>(`/api/console/targets/${encodeURIComponent(ref)}`, body as Record<string, unknown>),
  deleteTarget: (ref: string) =>
    deleteJSON(`/api/console/targets/${encodeURIComponent(ref)}`),
  disableTarget: (ref: string) =>
    postJSON<TargetEntry>(`/api/console/targets/${encodeURIComponent(ref)}/disable`, {}),
  enableTarget: (ref: string) =>
    postJSON<TargetEntry>(`/api/console/targets/${encodeURIComponent(ref)}/enable`, {}),
  // Typed assessment creation. It references a stable inventory target id; the controller enforces
  // that target's stored scope and fails closed on anything outside it.
  startAssessment: (body: {
    target_id: string
    profile_id: string
    request_budget: number
    max_duration_minutes: number
  }) =>
    postJSON<{ run_id: string; target_id: string; profile_id: string; status: string; request_budget: number; time_budget_ms: number }>(
      '/api/console/assessments',
      body,
    ),
  // BEAST disposable adversary sandbox. Every call maps to a controller-enforced boundary.
  beastConfig: () => getJSON<BeastConfig>('/api/beast/config'),
  beastPreflight: (targetRef: string) =>
    getJSON<BeastPreflight>(`/api/beast/preflight/${encodeURIComponent(targetRef)}`),
  beastIssueLease: (body: {
    operator_id: string
    actor_type: 'OPERATOR'
    target_ref: string
    profile_id: string
    // Optional operator-facing TOOLBOX profile id (e.g. OUTSIDE_IN_WEB_DISCOVERY_V1). When set,
    // the server narrows the lease to that profile's bound scenario.
    operator_profile_id?: string
    confirmation: string
    requested_resources?: BeastResourceEnvelope
  }) => postJSON<BeastLease>('/api/beast/leases', body),
  beastCreateRun: (body: { lease_id: string; scenario_id: string }) =>
    postJSON<BeastRunView>('/api/beast/runs', body),
  beastRun: (runId: string) =>
    getJSON<BeastRunDetail>(`/api/beast/runs/${encodeURIComponent(runId)}`),
  beastStop: (runId: string, operatorId: string) =>
    postJSON<BeastRunView>(`/api/beast/runs/${encodeURIComponent(runId)}/stop`, {
      operator_id: operatorId,
    }),
}
