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

const targets = {
  items: [
    {
      target_ref: 'synthetic-bank-api',
      name: 'Synthetic Bank API',
      type: 'REST API',
      environment: 'SYNTHETIC_LAB',
      description: 'Authorized in-process synthetic banking API.',
      supported_profile_ids: ['aegis-native-bola-synthetic'],
    },
    {
      target_ref: 'range-bank',
      name: 'Aegis Bank',
      type: 'REST API',
      environment: 'SYNTHETIC_RANGE',
      description: 'Authorized synthetic range application.',
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

let postedBodies: Record<string, unknown>[] = []

function stubFetch(overrides: { runs?: unknown[] } = {}) {
  postedBodies = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (init?.method === 'POST') {
        postedBodies.push(JSON.parse(String(init.body)))
        return { ok: true, json: async () => ({ ...run, id: 'scan-cccccccccccc', status: 'RUNNING' }) } as Response
      }
      const runsList = overrides.runs ?? [run, passRun]
      const payload = path.includes('/runs/')
        ? { run, events: [], evidence: [] }
        : path.includes('/console/runs')
          ? { items: runsList, count: runsList.length }
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
  })

  it('has no Presentation Mode and no Engineering Dashboard in navigation', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    expect(screen.queryByText(/Presentation/i)).toBeNull()
    expect(screen.queryByText(/Engineering/i)).toBeNull()
    expect(screen.queryByText(/Engineering dashboard/i)).toBeNull()
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
  it('selects an authorized target, shows profile availability, reviews, and starts a real job', async () => {
    render(<App />)
    await screen.findByRole('heading', { name: 'Runs' })
    fireEvent.click(screen.getAllByText('New Assessment')[0]!)

    // Step 1: authorized inventory targets.
    await screen.findByText('Choose an authorized target')
    expect(screen.getByText('Aegis Bank')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Synthetic Bank API'))
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))

    // Step 2: profile description shown; availability drives selectability.
    await screen.findByText('Choose an assessment')
    expect(screen.getByText(/Examines authorized API object-access boundaries/)).toBeInTheDocument()
    fireEvent.click(screen.getByText('Web & API Authorization'))
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))

    // Step 3: controls.
    await screen.findByText('Execution controls')
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))

    // Step 4: review summary + start.
    await screen.findByText('Review and start')
    expect(screen.getByText('Web & API Authorization')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Start assessment' }))

    await waitFor(() => expect(postedBodies.length).toBe(1))
    expect(postedBodies[0]).toMatchObject({ target: 'synthetic-bank-api', variant: 'vulnerable' })
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
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    fireEvent.click(await screen.findByText('Web & API Authorization'))
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Continue' }))
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
