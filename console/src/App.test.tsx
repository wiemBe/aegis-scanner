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
