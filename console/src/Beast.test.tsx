import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { BeastConsole } from './Beast'

const TARGET_NAME = 'Disposable Synthetic Bank Adversary Target'
const REQUIRED_PHRASE = `ASSESS ${TARGET_NAME}`

const enabledConfig = {
  enabled: true,
  mode: 'SAFE_PASSIVE',
  available_mode: 'BEAST_ACTIVE',
  profile_id: 'BEAST_ADVERSARY_SANDBOX_V1',
  required_model: 'qwen3:8b',
  synthetic_lab_only: true,
  target_refs: ['beast-synthetic-vulnerable'],
  tools: [
    { name: 'curl', category: 'http-client', purpose: 'Issue bounded HTTP requests.', source: 'debian' },
    { name: 'httpie', category: 'http-client', purpose: 'Inspect HTTP responses.', source: 'debian' },
    { name: 'httpx', category: 'http-prober', purpose: 'Probe observed paths.', source: 'github' },
    { name: 'katana', category: 'web-crawler', purpose: 'Crawl the authorized surface.', source: 'github' },
    { name: 'akca', category: 'dast-scanner', purpose: 'Run contextual DAST checks.', source: 'github' },
    { name: 'ffuf', category: 'content-discovery', purpose: 'Discover content.', source: 'debian' },
    { name: 'gobuster', category: 'content-discovery', purpose: 'Enumerate paths.', source: 'debian' },
    { name: 'nuclei', category: 'template-scanner', purpose: 'Run detection templates.', source: 'github' },
    { name: 'sqlmap', category: 'injection-probe', purpose: 'Probe SQL injection.', source: 'debian' },
  ],
  technical_subtitle: 'Disposable AI Adversary Sandbox',
  boundary_description: 'Unrestricted attack logic inside a strictly bounded execution environment.',
}

const preflight = {
  profile_id: 'BEAST_ADVERSARY_SANDBOX_V1',
  mode: 'BEAST_ACTIVE',
  target: {
    target_ref: 'beast-synthetic-vulnerable',
    name: TARGET_NAME,
    origin: 'http://beast-target:8080',
    base_path: '/lab/beast/vulnerable',
    environment: 'SYNTHETIC_LAB',
    allowed_methods: ['GET', 'HEAD', 'OPTIONS'],
    allowed_path_prefix: '/lab/beast/vulnerable',
    prohibited_operations: ['denial of service'],
    synthetic_data_only: true,
    health: 'GREEN',
    expected_impact: 'Bounded requests to a synthetic fixture',
    max_blast_radius: 'One internal synthetic target service',
  },
  enabled_capabilities: ['endpoint_discovery', 'bola_readonly', 'safe_injection'],
  enabled_engines: ['AI_ADVERSARY_SHELL', 'DETERMINISTIC_VERIFIER'],
  resources: {
    total_wall_time_seconds: 180,
    per_command_timeout_seconds: 20,
    max_commands: 8,
    max_request_rate_per_second: 4,
    max_target_connections: 40,
  },
  automatic_expiry_seconds: 900,
  emergency_stop: 'Revoke the lease, kill the process tree, disarm target access.',
  technical_subtitle: 'Disposable AI Adversary Sandbox',
  boundary_description: 'Unrestricted attack logic inside a strictly bounded execution environment.',
}

const CROSS_OWNER_CMD = "curl -s -H 'Authorization: Bearer lab-token-user-a' http://beast-target:8080/lab/beast/vulnerable/accounts/B-200"

const runView = {
  run_id: 'beast-run-abc',
  lease_id: 'beast-lease-xyz',
  target_ref: 'beast-synthetic-vulnerable',
  scenario_id: 'bola_readonly',
  state: 'VERIFIED',
  model: 'qwen3:8b',
  stop_reason: 'VERIFIER_CONFIRMED',
  workspace_destroyed: true,
  cleanup_verified: true,
  emergency_stopped: false,
  commands: [
    {
      command_id: 'cmd-1',
      parent_command_id: null,
      sequence: 1,
      command_text: CROSS_OWNER_CMD,
      expected_intent: 'Read a user B object as user A.',
      hypothesis_reference: 'A cross-owner read may lack an ownership check.',
    },
  ],
  observations: [
    {
      observation_id: 'obs-1',
      command_id: 'cmd-1',
      sequence: 1,
      summary: 'Command 1 exited 0',
      command_text: CROSS_OWNER_CMD,
      facts: { exit_code: 0, http_status_codes: [200], contains_user_b_owner: true },
      stdout: '{"account_id":"B-200","owner_id":"user-b"}',
      stderr: '',
      artifact_previews: {},
    },
  ],
  model_calls: [
    {
      sequence: 1,
      model: 'qwen3:8b',
      usage: { input_tokens: 30, output_tokens: 12, total_tokens: 42 },
      metadata: { total_duration_ms: 10, prompt_eval_count: 30, eval_count: 12 },
      decision_type: 'command',
      input_observation_ids: [],
    },
    {
      sequence: 2,
      model: 'qwen3:8b',
      usage: { input_tokens: 40, output_tokens: 8, total_tokens: 48 },
      metadata: { total_duration_ms: 9 },
      decision_type: 'stop',
      input_observation_ids: ['obs-1'],
    },
  ],
  verifier_conclusion: { status: 'CONFIRMED', authority: 'DETERMINISTIC_VERIFIER' },
  created_at: '2026-09-28T10:00:00Z',
  completed_at: '2026-09-28T10:00:05Z',
}

const runEvents = [
  { sequence: 1, event_id: 'e1', run_id: 'beast-run-abc', event_type: 'AI_SHELL_COMMAND_COMPLETED', actor_type: 'SANDBOX_SUPERVISOR', timestamp: '2026-09-28T10:00:03Z', details: {} },
  { sequence: 2, event_id: 'e2', run_id: 'beast-run-abc', event_type: 'AI_ADVERSARY_STOPPED', actor_type: 'AI_MODEL', timestamp: '2026-09-28T10:00:04Z', details: { hypothesis: 'The direct response is sufficient.', summary: 'Stop after the cross-owner response.', evidence_observation_ids: ['obs-1'] } },
  { sequence: 3, event_id: 'e3', run_id: 'beast-run-abc', event_type: 'VERIFICATION_COMPLETED', actor_type: 'VERIFIER', timestamp: '2026-09-28T10:00:05Z', details: {} },
]

let posted: { path: string; body: unknown }[] = []

function stub(config: Record<string, unknown>) {
  posted = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (init?.method === 'POST') {
        posted.push({ path, body: JSON.parse(String(init.body)) })
        if (path.includes('/leases')) {
          return { ok: true, json: async () => ({ lease_id: 'beast-lease-xyz', state: 'ACTIVE', target_ref: 'beast-synthetic-vulnerable', profile_id: 'BEAST_ADVERSARY_SANDBOX_V1', capability_set: ['bola_readonly'], expires_at: '2026-09-28T10:15:00Z' }) } as Response
        }
        if (path.includes('/runs')) {
          return { ok: true, json: async () => runView } as Response
        }
        return { ok: true, json: async () => ({}) } as Response
      }
      const payload = path.includes('/beast/config')
        ? config
        : path.includes('/beast/preflight/')
          ? preflight
          : path.includes('/beast/runs/')
            ? { run: runView, events: runEvents }
            : {}
      return { ok: true, json: async () => payload } as Response
    }),
  )
}

beforeEach(() => stub(enabledConfig))
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('BEAST console panel', () => {
  it('shows a fail-closed disabled state when BEAST is off', async () => {
    stub({ ...enabledConfig, enabled: false })
    render(<BeastConsole />)
    expect(await screen.findByText(/disposable toolbox is unavailable/i)).toBeInTheDocument()
    expect(screen.queryByText('beast-synthetic-vulnerable')).not.toBeInTheDocument()
    expect(screen.getByText('Installed sandbox toolbox')).toBeInTheDocument()
    for (const tool of enabledConfig.tools) {
      expect(screen.getByText(tool.name)).toBeInTheDocument()
    }
  })

  it('gates activation behind the exact typed confirmation phrase', async () => {
    render(<BeastConsole />)
    fireEvent.click(await screen.findByText('beast-synthetic-vulnerable'))

    // Controls + the exact required phrase are shown after preflight.
    await screen.findByText(/Type the exact confirmation phrase/i)
    expect(screen.getByText(REQUIRED_PHRASE)).toBeInTheDocument()

    const activate = screen.getByRole('button', { name: /Start toolbox assessment/i })
    expect(activate).toBeDisabled()

    fireEvent.change(screen.getByPlaceholderText('e.g. operator-1'), { target: { value: 'operator-1' } })
    fireEvent.change(screen.getByLabelText('Scenario'), { target: { value: 'bola_readonly' } })
    fireEvent.change(screen.getByPlaceholderText('Type the phrase exactly'), { target: { value: 'ASSESS wrong phrase' } })
    expect(activate).toBeDisabled()

    fireEvent.change(screen.getByPlaceholderText('Type the phrase exactly'), { target: { value: REQUIRED_PHRASE } })
    await waitFor(() => expect(activate).not.toBeDisabled())
  })

  it('issues a lease then a run with the operator confirmation, and surfaces the verifier outcome', async () => {
    render(<BeastConsole />)
    fireEvent.click(await screen.findByText('beast-synthetic-vulnerable'))
    await screen.findByText(/Type the exact confirmation phrase/i)
    fireEvent.change(screen.getByPlaceholderText('e.g. operator-1'), { target: { value: 'operator-1' } })
    fireEvent.change(screen.getByLabelText('Scenario'), { target: { value: 'bola_readonly' } })
    fireEvent.change(screen.getByPlaceholderText('Type the phrase exactly'), { target: { value: REQUIRED_PHRASE } })
    fireEvent.click(screen.getByRole('button', { name: /Start toolbox assessment/i }))

    await screen.findByText('beast-run-abc')
    // Verifier outcome is surfaced, not self-asserted by the run.
    expect(screen.getByText('CONFIRMED')).toBeInTheDocument()

    // Debug transcript renders the AI input/decision/result per turn.
    expect(screen.getByText(/Model transcript/i)).toBeInTheDocument()
    expect(screen.getAllByText('SENT TO MODEL').length).toBeGreaterThan(0)
    expect(screen.getAllByText('AI DECISION').length).toBeGreaterThan(0)
    expect(screen.getAllByText(CROSS_OWNER_CMD).length).toBeGreaterThan(0)
    expect(screen.getByText('SANDBOX RESULT')).toBeInTheDocument()
    // The stop turn surfaces the model's cited evidence.
    expect(screen.getByText('Stop after the cross-owner response.')).toBeInTheDocument()

    const lease = posted.find((p) => p.path.includes('/leases'))?.body as Record<string, unknown>
    expect(lease).toMatchObject({
      actor_type: 'OPERATOR',
      target_ref: 'beast-synthetic-vulnerable',
      profile_id: 'BEAST_ADVERSARY_SANDBOX_V1',
      confirmation: REQUIRED_PHRASE,
    })
    const runReq = posted.find((p) => p.path.endsWith('/runs'))?.body as Record<string, unknown>
    expect(runReq).toMatchObject({ lease_id: 'beast-lease-xyz', scenario_id: 'bola_readonly' })
  })

  it('binds an embedded wizard launch to the selected assessment profile', async () => {
    // The NewAssessment wizard renders the embedded panel with the operator-facing TOOLBOX
    // profile: the lease carries operator_profile_id, the scenario is preselected and locked,
    // and the controller narrows the lease to exactly that profile's bound scenario.
    render(
      <BeastConsole
        embedded
        initialTargetRef="beast-synthetic-vulnerable"
        initialScenario="endpoint_discovery"
        operatorProfileId="OUTSIDE_IN_WEB_DISCOVERY_V1"
      />,
    )
    await screen.findByText(/Type the exact confirmation phrase/i)

    // The scenario is shown read-only, bound to the profile — no dropdown to change it.
    const scenarioField = screen.getByLabelText(/Scenario \(bound to the selected assessment profile\)/i)
    expect(scenarioField).toBeDisabled()
    expect(scenarioField).toHaveValue('Endpoint discovery')

    fireEvent.change(screen.getByPlaceholderText('e.g. operator-1'), { target: { value: 'operator-1' } })
    fireEvent.change(screen.getByPlaceholderText('Type the phrase exactly'), { target: { value: REQUIRED_PHRASE } })
    fireEvent.click(screen.getByRole('button', { name: /Start toolbox assessment/i }))

    await screen.findByText('beast-run-abc')
    const lease = posted.find((p) => p.path.includes('/leases'))?.body as Record<string, unknown>
    expect(lease).toMatchObject({ operator_profile_id: 'OUTSIDE_IN_WEB_DISCOVERY_V1' })
    const runReq = posted.find((p) => p.path.endsWith('/runs'))?.body as Record<string, unknown>
    expect(runReq).toMatchObject({ lease_id: 'beast-lease-xyz', scenario_id: 'endpoint_discovery' })
  })
})
