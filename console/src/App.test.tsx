import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { App } from './App'

// A secret value the browser must never receive or render, and a hostile string that must render
// as inert text.
const SECRET = 'super-secret-credential-value'
const hostile = '<img src=x onerror=alert(1)>'

const run = {
  id: 'scan-aaaaaaaaaaaa',
  status: 'FAIL',
  target_name: 'Synthetic Bank API',
  scope: 'approved',
  planner: 'DEMO_HEURISTIC',
  mode: 'DEMO_HEURISTIC',
  model: null,
  variant: 'vulnerable',
  scenario: 'positive_vulnerable',
  created_at: '2026-09-18T19:00:00Z',
  completed_at: '2026-09-18T19:00:04Z',
  planner_contract_version: 3,
  execution_policy_version: 1,
  usage: { requests: 4, model_calls: 0, reserved_tokens: 0, reported_tokens: 0 },
  budgets: { target_requests: 8, model_calls: 6, token_reservations: 80000 },
  candidate_counts: { generated: 1, validated: 1, rejected: 0 },
  safety_rejections: 0,
  finding_count: 1,
  finding_ids: ['finding-1'],
  retest_of: null,
  linked_retests: [],
  verification: 'CONFIRMED',
  terminal_reason: 'DETERMINISTIC_CONFIRMED',
  engine: 'AEGIS_NATIVE',
  adapter_version: 'aegis-native/1.1.0',
  tool_reported_count: 1,
  verifier_confirmed_count: 1,
}

const passRun = { ...run, id: 'scan-bbbbbbbbbbbb', status: 'PASS', finding_count: 0, verification: null }

const confirmedFinding = {
  id: 'finding-1',
  severity: 'HIGH',
  confidence: 'CONFIRMED',
  status: 'CONFIRMED',
  vulnerability_class: 'API1:2023 BOLA',
  owasp_mapping: 'API1:2023 Broken Object Level Authorization',
  source_engine: 'AEGIS_NATIVE',
  affected_operation: 'GET /api/v1/accounts/{account_id}',
  principal_object_direction: 'user_a → user_b',
  discovery_scan: run.id,
  linked_retest: null,
  evidence_completeness: 'PARTIAL',
  created_at: run.created_at,
  updated_at: run.completed_at,
  title: hostile,
  provenance: 'VERIFIER',
  ai_hypothesis: 'One direction',
  controller_execution: 'Three requests',
  deterministic_evidence: 'Vulnerable: 200 / 200 / 200',
  verifier_conclusion: 'Confirmed',
  patched_retest: 'Not run',
  final_state: 'FAIL',
}

const targetDefaults = {
  target_type: 'SYNTHETIC' as const,
  synthetic: true,
  status: 'AVAILABLE_FOR_ASSESSMENT',
  enabled: true,
  authorization_reference: 'SYNTHETIC_LAB_SCOPE',
  authorized_scope: ['synthetic-bank-api (in-process synthetic lab)'],
  allowed_path_prefixes: [] as string[],
  excluded_path_prefixes: [] as string[],
  credential_reference: null,
  last_assessment_at: null,
}

const targets = {
  custom_target_entry: true,
  items: [
    {
      ...targetDefaults,
      target_ref: 'synthetic-bank-api',
      name: 'Synthetic Bank API',
      type: 'REST API',
      environment: 'SYNTHETIC_LAB',
      description: 'Authorized in-process synthetic banking API.',
      supported_profile_ids: ['aegis-native-bola-synthetic'],
    },
    {
      ...targetDefaults,
      target_ref: 'range-bank',
      name: 'Aegis Bank',
      type: 'REST API',
      environment: 'SYNTHETIC_RANGE',
      description: 'Authorized synthetic range application.',
      authorized_scope: ['http://range-bank.local (synthetic range)'],
      supported_profile_ids: ['NUCLEI_LAB_SAFE_HTTP_V1'],
    },
  ],
}

const nativeCap = {
  capability_id: 'bola_object_read_v1',
  title: 'Object-level authorization read comparison (BOLA)',
  activity: 'ACTIVE',
  request_budget: 8,
  concurrency_budget: 1,
  time_budget_ms: 90000,
  requires_authentication: true,
  state_changing_possible: false,
  verified_severity: 'HIGH',
  required_approvals: ['SYNTHETIC_LAB_SCOPE'],
}

const profiles = {
  items: [
    {
      profile_id: 'aegis-native-bola-synthetic',
      display_name: 'Web & API Authorization',
      operator_summary: 'Examines authorized API object-access boundaries and produces hypotheses for independent verification.',
      how_it_runs: 'Runs the Aegis-native object-authorization capability.',
      advanced: false,
      engine: 'AEGIS_NATIVE',
      environment: 'SYNTHETIC_LAB',
      available: true,
      unavailable_reason: '',
      capabilities: [nativeCap],
      isolation_boundary: 'in-process',
    },
    {
      profile_id: 'NUCLEI_LAB_SAFE_HTTP_V1',
      display_name: 'Exposure & Misconfiguration Scan',
      operator_summary: 'Checks the authorized target for exposed source-control metadata.',
      how_it_runs: 'Runs one anonymous read-only request per admitted template.',
      advanced: false,
      engine: 'NUCLEI',
      environment: 'SYNTHETIC_LAB',
      available: false,
      unavailable_reason: 'The Nuclei adapter is not enabled in this deployment.',
      capabilities: [{ ...nativeCap, capability_id: 'nuclei_scm_metadata_exposure_v1' }],
      isolation_boundary: 'isolated runner',
    },
  ],
}

const toolboxHealth = {
  state: 'READY',
  checked_at: '2026-09-28T18:00:00Z',
  reason: '',
  ready: 3,
  total: 3,
  tools: [
    { name: 'ffuf', category: 'content-discovery', purpose: 'Discover content.', source: 'debian', status: 'READY', detail: 'ffuf v2.1.0' },
    { name: 'gobuster', category: 'content-discovery', purpose: 'Enumerate paths.', source: 'debian', status: 'READY', detail: 'gobuster 3.6' },
    { name: 'sqlmap', category: 'injection-probe', purpose: 'Probe SQL injection.', source: 'debian', status: 'READY', detail: '1.8' },
  ],
}

const aiCatalog = {
  provider: 'internal_openai_compatible',
  current_model: 'deepseek-v4-pro',
  models: ['deepseek-v4-pro', 'deepseek-chat', 'deepseek-reasoner'],
  runtime_switching: true,
}

const aiBalance = {
  provider: 'deepseek',
  state: 'AVAILABLE',
  available: true,
  balances: [{ currency: 'USD', remaining: '12.5000' }],
  checked_at: '2026-09-29T10:00:00Z',
}

let postedBodies: Record<string, unknown>[] = []

function stubFetch(overrides: { runs?: unknown[] } = {}) {
  postedBodies = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (init?.method === 'POST') {
        postedBodies.push(JSON.parse(String(init.body)))
        if (path.includes('/console/ai/select')) {
          const selected = String(postedBodies.at(-1)?.model)
          return {
            ok: true,
            json: async () => ({ ...aiCatalog, current_model: selected }),
          } as Response
        }
        if (path.includes('/console/ai/test')) {
          return {
            ok: true,
            json: async () => ({
              test_id: 'ai-test-aaaaaaaaaaaa', status: 'PASS', code: 'SYNTHETIC_AI_TEST_PASSED',
              provider: aiCatalog.provider, model: aiCatalog.current_model, decision_type: 'stop',
              usage: { input_tokens: 20, output_tokens: 5, total_tokens: 25 },
              fixture_state: 'DESTROYED', cleanup_verified: true, docker_resources_created: 0,
              started_at: '2026-09-29T10:00:00Z', completed_at: '2026-09-29T10:00:01Z',
            }),
          } as Response
        }
        return {
          ok: true,
          json: async () => ({
            run_id: 'scan-cccccccccccc',
            target_id: 'synthetic-bank-api',
            profile_id: 'aegis-native-bola-synthetic',
            status: 'RUNNING',
          }),
        } as Response
      }
      const runsList = overrides.runs ?? [run, passRun]
      const payload = path.includes('/runs/')
        ? { run, events: [], evidence: [] }
        : path.includes('/console/runs')
          ? { items: runsList, count: runsList.length }
          : path.includes('/console/toolbox/health')
            ? toolboxHealth
          : path.includes('/console/ai/models')
            ? aiCatalog
          : path.includes('/console/ai/balance')
            ? aiBalance
          : path.includes('/console/findings')
            ? { items: [confirmedFinding] }
            : path.includes('/console/targets')
              ? targets
              : path.includes('/console/profiles')
                ? profiles
                : path.includes('/console/audit')
                  ? { items: [] }
                  : path.includes('/console/health')
                    ? { control_plane: 'HEALTHY', lab: 'HEALTHY' }
                    : path.includes('/console/config')
                      ? { console_version: '1.0.0', operational_engines: ['AEGIS_NATIVE'] }
                      : {}
      return { ok: true, json: async () => payload } as Response
    }),
  )
}

beforeEach(() => {
  window.location.hash = ''
  stubFetch()
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('Operator console — landing and navigation', () => {
  it('shows a run-first landing with one obvious New Assessment action', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    expect(screen.getAllByRole('button', { name: 'New Assessment' }).length).toBeGreaterThan(0)
    expect(await screen.findByText('Recent runs')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'USD 12.5' })).toBeInTheDocument()
  })

  it('switches an allowlisted AI model and runs a self-cleaning synthetic test', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    const selector = await screen.findByRole('combobox', { name: 'AI model' })
    expect(selector).toHaveValue('deepseek-v4-pro')

    fireEvent.change(selector, { target: { value: 'deepseek-chat' } })
    await screen.findByText('deepseek-chat selected')
    expect(postedBodies).toContainEqual({ model: 'deepseek-chat' })

    fireEvent.click(screen.getByRole('button', { name: 'Test AI' }))
    expect(await screen.findByText(/AI test passed · fixture destroyed · no Docker resources/)).toBeInTheDocument()
  })

  it('has no Presentation Mode and no Engineering Dashboard in navigation', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    expect(screen.queryByText(/Presentation/i)).toBeNull()
    expect(screen.queryByText(/Engineering/i)).toBeNull()
    expect(screen.queryByText(/Engineering dashboard/i)).toBeNull()
    expect(screen.queryByRole('button', { name: 'BEAST Sandbox' })).toBeNull()
  })

  it('gates the Debug route behind the development build flag', async () => {
    // Debug is a development-only affordance guarded by import.meta.env.DEV. Vitest runs in DEV, so
    // here the Debug nav item is present; the production build (DEV=false) omits it entirely, which
    // is confirmed by the production build + visual verification.
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    if (import.meta.env.DEV) {
      expect(screen.getByRole('button', { name: 'Debug' })).toBeInTheDocument()
    } else {
      expect(screen.queryByRole('button', { name: 'Debug' })).toBeNull()
      window.location.hash = '#/debug'
      await waitFor(() => expect(screen.getByRole('heading', { name: 'Runs' })).toBeInTheDocument())
    }
  })
})

describe('New assessment workflow', () => {
  it('keeps the live-checked toolbox inside the normal assessment flow without a separate mode', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    fireEvent.click(screen.getAllByText('New Assessment')[0]!)

    expect(await screen.findByRole('heading', { name: 'Assessment toolbox' })).toBeInTheDocument()
    expect(screen.queryByRole('switch')).toBeNull()
    expect(screen.queryByText(/BEAST mode/i)).toBeNull()
    for (const tool of toolboxHealth.tools) {
      expect(screen.getByText(tool.name)).toBeInTheDocument()
      expect(screen.getByText(tool.detail)).toBeInTheDocument()
    }
    expect(screen.getAllByText('READY').length).toBeGreaterThanOrEqual(toolboxHealth.tools.length)
    expect(screen.getByRole('button', { name: 'Check tools' })).toBeInTheDocument()
  })

  it('selects an authorized target, shows profile availability, reviews, and starts a real job', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    fireEvent.click(screen.getAllByText('New Assessment')[0]!)

    // Screen 1: choose one controller-authorized inventory target.
    await screen.findByText('Choose an authorized target')
    expect(screen.getByText('Aegis Bank')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Choose scan template/ })).toBeDisabled()
    fireEvent.click(screen.getByText('Synthetic Bank API'))
    fireEvent.click(screen.getByRole('button', { name: /Choose scan template/ }))

    // Screen 2 is a scanner-style template library narrowed to compatible controller profiles.
    expect(await screen.findByRole('heading', { name: 'Scan templates' })).toBeInTheDocument()
    expect(await screen.findByText('Web & API Authorization')).toBeInTheDocument()
    expect(screen.queryByText('Exposure & Misconfiguration Scan')).not.toBeInTheDocument()
    expect(screen.getByText('Basic scan')).toBeInTheDocument()
    expect(screen.getByText(/Aegis native engine \(in-process\).*8 requests/)).toBeInTheDocument()
    fireEvent.click(screen.getByText('Web & API Authorization'))
    expect(screen.getByText(/Basic scan.*Read-only/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Configure scan/ }))

    // Screen 3: a Nessus-style configuration workspace keeps settings, credentials, checks and
    // advanced execution facts separate without inventing capabilities outside the profile.
    await screen.findByText('Execution controls')
    expect(screen.getByRole('button', { name: 'Credentials' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Checks' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Advanced' })).toBeInTheDocument()
    expect(screen.getByText(/It is not allowed to/i)).toBeInTheDocument()
    fireEvent.change(screen.getByRole('spinbutton', { name: /Target request budget/ }), {
      target: { value: '4' },
    })
    fireEvent.change(screen.getByRole('spinbutton', { name: /Maximum duration/ }), {
      target: { value: '1' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Start assessment' }))

    await waitFor(() => expect(postedBodies.length).toBe(1))
    // The browser sends a stable inventory target id and profile id — never an origin or a scanner
    // argument. The controller resolves and enforces the target's stored scope.
    expect(postedBodies[0]).toMatchObject({
      target_id: 'synthetic-bank-api',
      profile_id: 'aegis-native-bola-synthetic',
      request_budget: 4,
      max_duration_minutes: 1,
    })
  })

  it('prevents duplicate submits while a start is in flight', async () => {
    // Make the POST hang so the button stays in its pending state.
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input)
        if (init?.method === 'POST') {
          postedBodies.push(JSON.parse(String(init.body)))
          await new Promise(() => {}) // never resolves
        }
        const payload = path.includes('/console/runs')
          ? { items: [run], count: 1 }
          : path.includes('/console/ai/models')
            ? aiCatalog
          : path.includes('/console/findings')
            ? { items: [] }
            : path.includes('/console/targets')
              ? targets
              : path.includes('/console/profiles')
                ? profiles
                : path.includes('/console/health')
                  ? { control_plane: 'HEALTHY', lab: 'HEALTHY' }
                  : { console_version: '1.0.0', operational_engines: ['AEGIS_NATIVE'] }
        return { ok: true, json: async () => payload } as Response
      }),
    )
    postedBodies = []
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    fireEvent.click(screen.getAllByText('New Assessment')[0]!)
    await screen.findByText('Choose an authorized target')
    fireEvent.click(screen.getByText('Synthetic Bank API'))
    fireEvent.click(screen.getByRole('button', { name: /Choose scan template/ }))
    fireEvent.click(await screen.findByText('Web & API Authorization'))
    fireEvent.click(screen.getByRole('button', { name: /Configure scan/ }))
    await screen.findByText('Execution controls')
    const start = await screen.findByRole('button', { name: 'Start assessment' })
    fireEvent.click(start)
    const pending = await screen.findByRole('button', { name: 'Starting…' })
    fireEvent.click(pending)
    fireEvent.click(pending)
    await waitFor(() => expect(postedBodies.length).toBe(1))
  })
})

describe('Findings, run detail and honest states', () => {
  it('renders a confirmed finding distinctly and never as raw markup', async () => {
    const { container } = render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    fireEvent.click(screen.getByRole('button', { name: 'Findings' }))
    expect(await screen.findByText('CONFIRMED FINDING')).toBeInTheDocument()
    // Hostile finding title renders as inert text, not an <img>.
    expect(screen.getAllByText(hostile).length).toBeGreaterThan(0)
    expect(container.querySelector('img')).toBeNull()
  })

  it('shows the stop control disabled with an honest reason on a completed run', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    fireEvent.click(await screen.findByText(/scan-aaaaaaaaaaaa/))
    const stop = await screen.findByRole('button', { name: 'Stop assessment' })
    expect(stop).toBeDisabled()
    expect(screen.getByText(/Stop is unavailable/)).toBeInTheDocument()
  })

  it('shows cleanup as complete with no residual resources', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    fireEvent.click(await screen.findByText(/scan-aaaaaaaaaaaa/))
    fireEvent.click(await screen.findByRole('tab', { name: 'Cleanup' }))
    expect(await screen.findByText(/disposable containers or networks/)).toBeInTheDocument()
  })

  it('shows the AI input/decision transcript for a normal run', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    fireEvent.click(await screen.findByText(/scan-aaaaaaaaaaaa/))
    fireEvent.click(await screen.findByRole('tab', { name: 'Transcript' }))
    expect(await screen.findByText('AI reasoning chain')).toBeInTheDocument()
    expect(screen.getByText('AI HYPOTHESIS')).toBeInTheDocument()
    expect(screen.getByText('CONTROLLER EXECUTION')).toBeInTheDocument()
    expect(screen.getByText('Event transcript')).toBeInTheDocument()
  })

  it('offers a CSV export of the run ledger on the Runs page', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    const link = screen.getByRole('link', { name: 'Export CSV' })
    expect(link).toHaveAttribute('href', '/api/console/runs.csv')
  })
})

describe('Credential safety', () => {
  it('never renders a credential value present in run data', async () => {
    // Even if a hostile backend leaked a secret into a field, the console must not display it.
    const leaky = { ...run, scope: SECRET }
    stubFetch({ runs: [leaky] })
    const { container } = render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    expect(container.textContent).not.toContain(SECRET)
  })
})

describe('Company target onboarding', () => {
  const companyTarget = {
    ...targetDefaults,
    target_ref: 'tgt-abc123def456',
    target_type: 'WEBSITE' as const,
    synthetic: false,
    name: 'Company Marketing Site',
    type: 'Website / FQDN',
    environment: 'PRODUCTION',
    description: '',
    authorization_reference: 'CHG-1029',
    authorized_scope: ['https://example.company.com'],
    supported_profile_ids: ['NUCLEI_LAB_SAFE_HTTP_V1', 'ZAP_LAB_PASSIVE_OPENAPI_V1'],
  }

  function stubOnboarding() {
    postedBodies = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input)
        if (init?.method === 'POST') {
          postedBodies.push(JSON.parse(String(init.body)))
          if (path.endsWith('/targets/preview')) {
            return { ok: true, json: async () => ({
              authorized_scope: ['https://example.company.com'],
              origins: ['https://example.company.com'],
              addresses: [], wildcard_subdomains: [],
              allowed_path_prefixes: [], excluded_path_prefixes: [], openapi_url: null,
            }) } as Response
          }
          return { ok: true, json: async () => companyTarget } as Response
        }
        const payload = path.includes('/console/runs')
          ? { items: [run], count: 1 }
          : path.includes('/console/ai/models')
            ? aiCatalog
          : path.includes('/console/findings')
            ? { items: [] }
            : path.includes('/console/targets')
              ? targets
              : path.includes('/console/profiles')
                ? profiles
                : path.includes('/console/health')
                  ? { control_plane: 'HEALTHY', lab: 'HEALTHY' }
                  : { console_version: '1.0.0', operational_engines: ['AEGIS_NATIVE'] }
        return { ok: true, json: async () => payload } as Response
      }),
    )
  }

  it('offers Add authorized target on the target step and returns to the flow with it selected', async () => {
    stubOnboarding()
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    fireEvent.click(screen.getAllByText('New Assessment')[0]!)
    await screen.findByText('Choose an authorized target')

    // The onboarding action is visible on the target step — not hidden in advanced settings.
    fireEvent.click(screen.getByRole('button', { name: '+ Add authorized target' }))
    await screen.findByRole('dialog', { name: 'Add authorized target' })

    fireEvent.change(screen.getByPlaceholderText('Company Marketing Site'), {
      target: { value: 'Company Marketing Site' },
    })
    fireEvent.change(screen.getByPlaceholderText('CHG-1029 / ticket ID'), {
      target: { value: 'CHG-1029' },
    })
    fireEvent.change(screen.getByPlaceholderText(/example.company.com/), {
      target: { value: 'example.company.com' },
    })
    fireEvent.click(screen.getByLabelText('I confirm that I am authorized to assess these targets'))

    // Preview shows the controller-normalized scope before saving.
    fireEvent.click(screen.getByRole('button', { name: 'Preview scope' }))
    await screen.findByText('Normalized authorized scope')

    // Add and continue persists via the typed endpoint and returns to the flow with it selected.
    fireEvent.click(screen.getByRole('button', { name: 'Add and continue' }))
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Add authorized target' })).toBeNull(),
    )
    expect(await screen.findByText('Company Marketing Site')).toBeInTheDocument()

    // The flow returns on the target screen with the new target already selected. The following
    // template library shows its unavailable engine profiles honestly and blocks configuration.
    fireEvent.click(screen.getByRole('button', { name: /Choose scan template/ }))
    expect(await screen.findByText('Exposure & Misconfiguration Scan')).toBeInTheDocument()
    expect(screen.getAllByText('Unavailable').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: /Configure scan/ })).toBeDisabled()

    // The create posted a typed, bounded scope — an origin, never a scanner argument or secret.
    const createBody = postedBodies.find((b) => b.display_name === 'Company Marketing Site')
    expect(createBody).toMatchObject({
      target_type: 'WEBSITE',
      authorization_attested: true,
      origins: ['example.company.com'],
    })
    expect(JSON.stringify(postedBodies)).not.toContain(SECRET)
  })

  it('makes the Targets page functional with add and company/synthetic distinction', async () => {
    stubOnboarding()
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    fireEvent.click(screen.getByRole('button', { name: 'Targets' }))
    await screen.findByRole('heading', { name: 'Targets' })
    // The synthetic seed is labeled as such, and the add action is present.
    expect(screen.getByText('Synthetic Bank API')).toBeInTheDocument()
    expect(screen.getAllByText('Synthetic').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: '+ Add authorized target' })).toBeInTheDocument()
    // Seeded catalog targets state their immutability where the Edit/Enable/Delete actions would
    // be — the edit affordance is never silently missing — and no Edit is offered for them.
    expect(screen.getAllByText('Immutable').length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: 'Edit' })).toBeNull()
    // The seeded target's detail modal explains the same instead of hiding the actions quietly.
    fireEvent.click(screen.getAllByRole('button', { name: 'View' })[0]!)
    await screen.findByRole('dialog')
    expect(await screen.findByText(/Catalog-seeded target — immutable/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
  })

  it('edits and deletes an operator target with explicit name confirmation', async () => {
    let inventory = [companyTarget]
    const requests: { method: string; path: string; body?: Record<string, unknown> }[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input)
        const method = init?.method ?? 'GET'
        const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : undefined
        requests.push({ method, path, body })

        if (method === 'PUT') {
          const updated = { ...companyTarget, name: String(body?.display_name), owner: body?.owner }
          inventory = [updated]
          return { ok: true, json: async () => updated } as Response
        }
        if (method === 'DELETE') {
          inventory = []
          return { ok: true, status: 204 } as Response
        }

        const payload = path.includes('/console/runs')
          ? { items: [], count: 0 }
          : path.includes('/console/ai/models')
            ? aiCatalog
          : path.includes('/console/findings')
            ? { items: [] }
            : path.includes('/console/targets')
              ? { custom_target_entry: true, items: inventory }
              : path.includes('/console/profiles')
                ? profiles
                : path.includes('/console/health')
                  ? { control_plane: 'HEALTHY', lab: 'HEALTHY' }
                  : { console_version: '1.0.0', operational_engines: ['AEGIS_NATIVE'] }
        return { ok: true, json: async () => payload } as Response
      }),
    )

    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    fireEvent.click(screen.getByRole('button', { name: 'Targets' }))
    await screen.findByText('Company Marketing Site')
    // An operator-onboarded target is mutable: the edit affordance replaces the immutable marker.
    expect(screen.queryByText('Immutable')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
    await screen.findByRole('dialog', { name: 'Edit authorized target' })
    fireEvent.change(screen.getByDisplayValue('Company Marketing Site'), {
      target: { value: 'Renamed Company Site' },
    })
    fireEvent.click(screen.getByLabelText('I confirm that I am authorized to assess these targets'))
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(await screen.findByText('Renamed Company Site')).toBeInTheDocument()
    expect(requests.find((request) => request.method === 'PUT')?.body).toMatchObject({
      display_name: 'Renamed Company Site',
      origins: ['https://example.company.com'],
      authorization_attested: true,
    })

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    await screen.findByRole('dialog', { name: 'Delete authorized target' })
    const deleteButton = screen.getByRole('button', { name: 'Delete target' })
    expect(deleteButton).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Target name confirmation'), {
      target: { value: 'Renamed Company Site' },
    })
    fireEvent.click(deleteButton)

    await waitFor(() => expect(screen.queryByText('Renamed Company Site')).toBeNull())
    expect(requests.some((request) => request.method === 'DELETE')).toBe(true)
  })
})
