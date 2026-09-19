import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { App } from './App'

class FakeEventSource {
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  constructor(url: string) { void url; setTimeout(() => this.onopen?.(), 0) }
  addEventListener() { /* no live messages in unit tests */ }
  close() { /* no-op */ }
}

const run = {
  id: 'scan-aaaaaaaaaaaa', status: 'FAIL', target_name: 'Synthetic Bank API', scope: 'approved', planner: 'LOCAL_LLM', mode: 'LOCAL_LLM', model: 'qwen3:8b', model_digest: 'a'.repeat(64), variant: 'vulnerable', scenario: 'positive_vulnerable', created_at: '2026-09-18T19:00:00Z', completed_at: '2026-09-18T19:00:04Z', planner_contract_version: 3, execution_policy_version: 1, usage: { requests: 4, model_calls: 1, reserved_tokens: 2048, reported_tokens: 700 }, budgets: { target_requests: 8, model_calls: 6, token_reservations: 80000 }, candidate_counts: { generated: 1, validated: 1, rejected: 0 }, safety_rejections: 0, finding_count: 1, finding_ids: ['finding-1'], retest_of: null, linked_retests: ['scan-bbbbbbbbbbbb'], verification: 'CONFIRMED', terminal_reason: 'DETERMINISTIC_CONFIRMED', scope_badges: [],
}
const hostile = '<img src=x onerror=alert(1)>'
const event = { event_id: 'evt-000000000001', sequence: 1, timestamp: '2026-09-18T19:00:01Z', run_id: run.id, scan_id: run.id, finding_id: 'finding-1', retest_scan_id: null, parent_event_id: null, actor_type: 'AI_PLANNER', event_type: 'CANDIDATE_GENERATED', stage: 'AI_HYPOTHESIS', status: 'RECORDED', engine: 'AEGIS_NATIVE', summary: hostile, evidence_refs: [], redaction_status: 'REDACTED', metadata: {}, integrity: { algorithm: 'SHA-256', digest: 'b'.repeat(64) } }
const finding = { id: 'finding-1', severity: 'HIGH', confidence: 'CONFIRMED', status: 'REMEDIATED', vulnerability_class: 'BOLA', owasp_mapping: 'API1:2023', source_engine: 'AEGIS_NATIVE', affected_operation: 'GET /api/v1/accounts/{account_id}', principal_object_direction: 'user_a → user_b', discovery_scan: run.id, linked_retest: 'scan-bbbbbbbbbbbb', evidence_completeness: 'COMPLETE', created_at: run.created_at, updated_at: run.completed_at, title: 'Broken object authorization', provenance: 'VERIFIER', ai_hypothesis: 'One direction', controller_execution: 'Three requests', deterministic_evidence: 'Vulnerable: 200 / 200 / 200', verifier_conclusion: 'Confirmed', patched_retest: 'Patched: 200 / 200 / 403', final_state: 'PASS' }

beforeEach(() => {
  vi.stubGlobal('EventSource', FakeEventSource)
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input)
    const lifecycle = [{ normalized_id: 'scan-aaaaaaaaaaaa:k', engine: 'AEGIS_NATIVE', adapter_version: 'aegis-native/1.1.0', capability_id: 'bola_object_read_v1', lifecycle_state: 'VERIFIED', ai_hypothesis: 'One direction', controller_authorization: 'job x', engine_reported: 'API1:2023 BOLA: raw', aegis_finding_id: 'finding-1', severity: 'HIGH', confidence: 'CONFIRMED', provenance: 'VERIFIER', verifier_status: 'CONFIRMED' }]
    const executionPolicy = { engine: 'AEGIS_NATIVE', adapter_version: 'aegis-native/1.1.0', engine_kernel_version: 1, execution_policy_version: 1, jobs_created: [{ engine: 'AEGIS_NATIVE', job_id: 'job-000000000001', execution_id: 'exec-000000000001', status: 'COMPLETED', observation_count: 3, reported_finding_count: 1 }], jobs_rejected: [] }
    const engines = { items: [
      { engine: 'AEGIS_NATIVE', name: 'Aegis Native — synthetic BOLA', adapter_version: 'aegis-native/1.1.0', configured: true, reachable: true, enabled: true, authorized: true, state: 'ENABLED', detail: 'native', profile_id: 'aegis-native-bola-synthetic', environment: 'SYNTHETIC_LAB', isolation_boundary: 'in-process', capabilities: [], kernel_version: 1 },
      { engine: 'NUCLEI', name: 'Nuclei — lab-safe HTTP', adapter_version: 'nuclei-adapter/1.2.0', configured: true, reachable: true, enabled: true, authorized: true, state: 'ENABLED', detail: 'Pinned runner attested', profile_id: 'NUCLEI_LAB_SAFE_HTTP_V1', environment: 'SYNTHETIC_LAB', isolation_boundary: 'isolated sidecar', capabilities: [], kernel_version: 1, provenance: { pinned_engine_version: 'v3.11.1', attested_binary_sha256: 'f'.repeat(64), manifest_version: '1.2.0', manifest_digest: 'c'.repeat(64), admitted_template_count: 1, signature_probe: 'SIGNED_VERIFIED', last_health_check: run.completed_at, latest_execution: { scan_id: 'scan-nucleinuclei', status: 'FAIL', http_connections: 1, request_budget: 1, records: 1, tool_reported: 1, verifier_confirmed: 1 }, responsibility: 'Nuclei is an Aegis-controlled detection engine. Its results are independently correlated and verified; Nuclei does not directly confirm Aegis findings.' } },
      { engine: 'ZAP', name: 'ZAP — passive scan (disabled)', adapter_version: 'zap-adapter/0.0.0-disabled', configured: true, reachable: null, enabled: false, authorized: false, state: 'DISABLED', detail: 'planned', profile_id: 'zap-passive-synthetic', environment: 'SYNTHETIC_LAB', isolation_boundary: 'FUTURE isolated sidecar', capabilities: [], kernel_version: 1 },
    ] }
    const payload = path.includes('/runs/') ? { run, events: [event], evidence: [], lifecycle, execution_policy: executionPolicy } : path.includes('/runs') ? { items: [run] } : path.includes('/audit') ? { items: [event] } : path.includes('/findings') ? { items: [finding] } : path.includes('/engines') ? engines : path.includes('/integrations') ? { items: [{ name: 'Aegis Native', engine: 'AEGIS_NATIVE', state: 'CONNECTED' }, { name: 'Nuclei', engine: 'NUCLEI', state: 'CONNECTED' }, { name: 'ZAP', engine: 'ZAP', state: 'PLANNED_NOT_CONNECTED' }] } : path.includes('/health') ? { checked_at: run.completed_at, control_plane: 'HEALTHY', gateway: 'HEALTHY', ollama: 'HEALTHY', lab: 'HEALTHY', dashboard_api: 'HEALTHY', database: 'HEALTHY', network_isolation: 'CONFIGURED_NOT_RUNTIME_ATTESTED', last_topology_test: 'NOT_AVAILABLE_IN_RUNTIME', last_secret_scan: 'NOT_AVAILABLE_IN_RUNTIME', event_stream: {}, evidence_storage: {} } : { enabled: false }
    return { ok: true, json: async () => payload } as Response
  }))
})
afterEach(() => cleanup())

describe('Operator Console', () => {
  it('renders mission state and permanent scope labels', async () => {
    render(<App />)
    expect(await screen.findByText('RESPONSIBILITY-AWARE WORKFLOW')).toBeInTheDocument()
    expect(screen.getAllByText('SYNTHETIC LAB').length).toBeGreaterThan(0)
    expect(screen.getByText('AI proposed')).toBeInTheDocument()
  })

  it('navigates to disconnected integrations without calling them operational', async () => {
    render(<App />)
    await screen.findByText('RESPONSIBILITY-AWARE WORKFLOW')
    fireEvent.click(screen.getByRole('button', { name: /Integrations/ }))
    expect(screen.getByText('PLANNED NOT CONNECTED')).toBeInTheDocument()
  })

  it('renders hostile event text as text, never markup', async () => {
    const { container } = render(<App />)
    await screen.findByText('RESPONSIBILITY-AWARE WORKFLOW')
    fireEvent.click(screen.getByRole('button', { name: /Audit/ }))
    expect(screen.getByText(hostile)).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
  })

  it('shows disabled engine adapters with honest four-state readiness', async () => {
    render(<App />)
    await screen.findByText('RESPONSIBILITY-AWARE WORKFLOW')
    fireEvent.click(screen.getByRole('button', { name: /Integrations/ }))
    expect(await screen.findByText('Engine adapters')).toBeInTheDocument()
    expect(screen.getAllByText('ENABLED')).toHaveLength(2)
    expect(screen.getByText('DISABLED')).toBeInTheDocument()
    expect(screen.getAllByText('Authorized').length).toBeGreaterThan(0)
    expect(screen.getByText(/Future isolation boundary/)).toBeInTheDocument()
    expect(screen.getByText('v3.11.1 · ffffffffffffffffffff…')).toBeInTheDocument()
    expect(screen.getByText(/1 tool-reported · 1 verifier-confirmed/)).toBeInTheDocument()
    expect(screen.getByText(/Nuclei does not directly confirm/)).toBeInTheDocument()
  })

  it('separates tool-reported from verifier-confirmed in the run replay lifecycle', async () => {
    render(<App />)
    await screen.findByText('RESPONSIBILITY-AWARE WORKFLOW')
    fireEvent.click(screen.getByRole('button', { name: /Runs/ }))
    fireEvent.click(await screen.findByText(/scan-aaaaaaaaaaaa/))
    expect(await screen.findByText('Tool-reported vs verifier-confirmed')).toBeInTheDocument()
    expect(screen.getByText('Deterministic decisions')).toBeInTheDocument()
    expect(screen.getAllByText('VERIFIER').length).toBeGreaterThan(0)
  })

  it('shows honest limitations in presentation mode', async () => {
    render(<App />)
    await screen.findByText('RESPONSIBILITY-AWARE WORKFLOW')
    fireEvent.click(screen.getByRole('button', { name: 'Presentation mode' }))
    expect(screen.getByText('Not production readiness')).toBeInTheDocument()
    expect(screen.getByText('No broad vulnerability coverage')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('The system proves.')).toBeInTheDocument())
  })
})

describe('Operator Console — Phase 1.3 ZAP passive integration', () => {
  const zapRun = { ...run, id: 'scan-zzzzzzzzzzzz', engine: 'ZAP', adapter_version: 'zap-adapter/1.3.0', target_name: 'Synthetic ZAP passive header scenario (vulnerable)', finding_count: 1, zap: { profile_id: 'ZAP_LAB_PASSIVE_OPENAPI_V1', profile_version: '1.3.0', engine_version: '2.17.0', image_index_digest: 'sha256:781a2bdaea47', projection_digest: 'd'.repeat(64), operation_count: 2, imported_urls: 2, expected_requests: 2, observed_requests: 2, blocked_requests: 0, passive_queue_drained: true, plan_validated: true, tool_reported_alerts: 1, correlated_alerts: 1, verifier_confirmed: 1, coverage_state: 'COMPLETE', exit_class: 'OK', error_code: null, rules: [{ plugin_id: 10021, name: 'X-Content-Type-Options Header Missing' }] } }
  const zapEvent = { ...event, event_id: 'evt-000000000009', scan_id: zapRun.id, run_id: zapRun.id, actor_type: 'TOOL_RUNNER', event_type: 'ZAP_ALERT_REPORTED', stage: 'TOOL_FINDING', engine: 'ZAP', summary: 'ZAP reported an untrusted passive alert (TOOL_REPORTED only).' }
  const alertCard = { artifact_type: 'ZAP_ALERT_CARD', artifact_id: `${zapRun.id}:zap-alert-0`, scan_id: zapRun.id, method: 'GET', normalized_route: '/lab/zap/vulnerable/catalog/synthetic-catalog-1', principal_profile_name: 'anonymous', object_reference: 'synthetic-zap-vulnerable', response_status: null, response_size: null, response_characteristics: { bounded: true, body_redacted: true }, timestamp: zapRun.completed_at, request_id: 'e'.repeat(24), evidence_hash: 'f'.repeat(64), control_probe_role: 'TOOL ALERT · UNTRUSTED', provenance: 'TOOL_REPORTED', plugin_id: 10021, rule_name: hostile, claimed_risk: 'high', claimed_confidence: 'medium' }
  const probeCard = { ...alertCard, artifact_type: 'VERIFIER_PROBE_CARD', artifact_id: `${zapRun.id}:verify-header`, provenance: 'VERIFIER', control_probe_role: 'VERIFIER PROBE', response_status: 200, property_observed: 'HEADER_ABSENT', rule_name: undefined }
  const zapEngine = { engine: 'ZAP', name: 'ZAP — lab passive OpenAPI (pinned, projected, read-only)', adapter_version: 'zap-adapter/1.3.0', configured: true, reachable: true, enabled: true, authorized: true, state: 'ENABLED', detail: 'Isolated runner attested', profile_id: 'ZAP_LAB_PASSIVE_OPENAPI_V1', environment: 'SYNTHETIC_LAB', isolation_boundary: 'isolated runner + scope guard', capabilities: [], kernel_version: 1, provenance: { pinned_engine_version: '2.17.0', pinned_image_index_digest: 'sha256:781a2bdaea47324e7bab583e2263f21d', add_on_inventory_digest: 'a'.repeat(64), attested_add_on_inventory_digest: 'a'.repeat(64), profile_id: 'ZAP_LAB_PASSIVE_OPENAPI_V1', profile_version: '1.3.0', approved_rule_count: 1, guard_version: 'zap-scope-guard/1.3.0', guard_reachable: true, last_health_check: zapRun.completed_at, latest_execution: { scan_id: zapRun.id, status: 'PASS', projection_digest: 'd'.repeat(64), operation_count: 2, imported_urls: 2, expected_requests: 2, observed_requests: 2, passive_queue_drained: true, tool_reported: 0, correlated: 0, verifier_confirmed: 0, coverage_state: 'COMPLETE' }, responsibility: 'ZAP passively analyzes responses from controller-approved read-only API operations. ZAP alerts are independently correlated and verified by Aegis.' } }

  const stub = () => vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const path = String(input)
    const payload = path.includes('/runs/') ? { run: zapRun, events: [zapEvent], evidence: [alertCard, probeCard], lifecycle: [], execution_policy: { engine: 'ZAP', adapter_version: 'zap-adapter/1.3.0', engine_kernel_version: 1, execution_policy_version: 1, jobs_created: [], jobs_rejected: [] } } : path.includes('/runs') ? { items: [zapRun] } : path.includes('/audit') ? { items: [zapEvent] } : path.includes('/findings') ? { items: [] } : path.includes('/engines') ? { items: [zapEngine] } : path.includes('/integrations') ? { items: [{ name: 'ZAP', engine: 'ZAP', state: 'CONNECTED' }] } : path.includes('/health') ? { checked_at: run.completed_at } : { enabled: false }
    return { ok: true, json: async () => payload } as Response
  }))

  it('shows ZAP pins, passive coverage and the responsibility boundary', async () => {
    stub()
    render(<App />)
    expect(await screen.findByText('Passive analysis of approved read-only operations')).toBeInTheDocument()
    expect(screen.getByText('COVERAGE COMPLETE')).toBeInTheDocument()
    expect(screen.getByText('OPENAPI PROJECTION')).toBeInTheDocument()
    expect(screen.getByText('PASSIVE SCAN')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Integrations/ }))
    expect(await screen.findByText("ZAP 2.17.0 · sha256:781a2bdaea47324…")).toBeInTheDocument()
    expect(screen.getByText('ZAP_LAB_PASSIVE_OPENAPI_V1 · v1.3.0')).toBeInTheDocument()
    expect(screen.getByText(/2 observed \/ 2 expected · queue drained YES/)).toBeInTheDocument()
    expect(screen.getAllByText(/ZAP alerts are independently correlated and verified by Aegis/).length).toBeGreaterThan(0)
    expect(screen.queryByText(/active scan(ning)? (is )?enabled/i)).toBeNull()
  })

  it('renders untrusted ZAP alert content as text, never markup', async () => {
    stub()
    const { container } = render(<App />)
    await screen.findByText('Passive analysis of approved read-only operations')
    fireEvent.click(screen.getByRole('button', { name: /Runs/ }))
    fireEvent.click(await screen.findByText(/scan-zzzzzzzzzzzz/))
    expect(await screen.findByText(`10021 · ${hostile}`)).toBeInTheDocument()
    expect(screen.getByText('risk high · confidence medium')).toBeInTheDocument()
    expect(screen.getByText('HEADER_ABSENT')).toBeInTheDocument()
    expect(screen.getByText('ZAP_ALERT_CARD')).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
  })
})
