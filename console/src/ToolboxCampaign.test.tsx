import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AssessmentProfile, BeastRunView, TargetEntry } from './api'
import { consoleApi } from './api'
import { ToolboxCampaign } from './ToolboxCampaign'

const target: TargetEntry = {
  target_ref: 'beast-synthetic-vulnerable',
  name: 'Disposable Toolbox Lab (Vulnerable)',
  type: 'Toolbox-enabled REST API',
  target_type: 'SYNTHETIC',
  environment: 'SYNTHETIC_LAB',
  description: 'Synthetic toolbox target',
  supported_profile_ids: ['DISCOVERY', 'EXPOSURE'],
  synthetic: true,
  status: 'AVAILABLE_FOR_ASSESSMENT',
  enabled: true,
  authorization_reference: 'BEAST_SCOPE',
  authorized_scope: ['http://beast-target/lab/beast/vulnerable'],
  allowed_path_prefixes: ['/lab/beast/vulnerable'],
  excluded_path_prefixes: [],
  credential_reference: null,
  last_assessment_at: null,
}

function profile(profileId: string, name: string): AssessmentProfile {
  return {
    profile_id: profileId,
    display_name: name,
    operator_summary: name,
    how_it_runs: 'Inside the disposable toolbox.',
    advanced: true,
    engine: 'TOOLBOX',
    environment: 'AUTHORIZED_INVENTORY',
    available: true,
    unavailable_reason: '',
    capabilities: [{
      capability_id: profileId.toLowerCase(),
      title: name,
      activity: 'ACTIVE',
      request_budget: 40,
      concurrency_budget: 2,
      time_budget_ms: 180_000,
      requires_authentication: false,
      state_changing_possible: false,
      verified_severity: 'UNKNOWN',
      required_approvals: ['TOOLBOX_PREFLIGHT'],
    }],
    isolation_boundary: 'Disposable sandbox',
    tools: ['curl'],
  }
}

function completedRun(runId: string, leaseId: string, scenario: string): BeastRunView {
  return {
    run_id: runId,
    lease_id: leaseId,
    target_ref: target.target_ref,
    scenario_id: scenario,
    state: 'PASS',
    model: 'test-model',
    stop_reason: null,
    workspace_destroyed: true,
    cleanup_verified: true,
    emergency_stopped: false,
    commands: [],
    observations: [],
    model_calls: [],
    verifier_conclusion: { status: 'PASS' },
    created_at: '2026-09-29T00:00:00Z',
    completed_at: '2026-09-29T00:00:01Z',
  }
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('ToolboxCampaign', () => {
  it('runs every template sequentially with its own profile-bound lease', async () => {
    const profiles = [profile('DISCOVERY', 'Discovery'), profile('EXPOSURE', 'Exposure')]
    const scenarios = { DISCOVERY: 'endpoint_discovery', EXPOSURE: 'information_exposure' }
    vi.spyOn(consoleApi, 'beastConfig').mockResolvedValue({
      enabled: true,
      mode: 'BEAST_ACTIVE',
      available_mode: 'BEAST_ACTIVE',
      profile_id: 'BEAST_ADVERSARY_SANDBOX_V1',
      required_model: 'test-model',
      synthetic_lab_only: true,
      target_refs: [target.target_ref],
      tools: [],
      technical_subtitle: 'Bounded toolbox',
      boundary_description: 'Synthetic only.',
    })
    vi.spyOn(consoleApi, 'beastPreflight').mockResolvedValue({
      profile_id: 'BEAST_ADVERSARY_SANDBOX_V1',
      mode: 'BEAST_ACTIVE',
      target: {
        target_ref: target.target_ref,
        name: target.name,
        origin: 'http://beast-target',
        base_path: '/lab/beast/vulnerable',
        environment: 'SYNTHETIC_LAB',
        allowed_methods: ['GET', 'HEAD', 'OPTIONS'],
        allowed_path_prefix: '/lab/beast/vulnerable',
        prohibited_operations: [],
        synthetic_data_only: true,
        health: 'GREEN',
        expected_impact: 'Read-only',
        max_blast_radius: 'One synthetic target',
      },
      enabled_capabilities: Object.values(scenarios),
      enabled_engines: ['curl'],
      resources: {
        total_wall_time_seconds: 180,
        per_command_timeout_seconds: 20,
        max_commands: 8,
        max_request_rate_per_second: 4,
        max_target_connections: 40,
      },
      automatic_expiry_seconds: 900,
      emergency_stop: 'Available',
      technical_subtitle: 'Bounded toolbox',
      boundary_description: 'Synthetic only.',
    })
    const lease = vi.spyOn(consoleApi, 'beastIssueLease')
      .mockImplementation(async (body) => ({
        lease_id: `lease-${body.operator_profile_id}`,
        state: 'ACTIVE',
        target_ref: target.target_ref,
        profile_id: 'BEAST_ADVERSARY_SANDBOX_V1',
        capability_set: [scenarios[body.operator_profile_id as keyof typeof scenarios]],
        expires_at: '2026-09-29T00:15:00Z',
      }))
    vi.spyOn(consoleApi, 'beastCreateRun').mockImplementation(async (body) => (
      completedRun(`run-${body.scenario_id}`, body.lease_id, body.scenario_id)
    ))

    render(<ToolboxCampaign target={target} profiles={profiles} scenarios={scenarios} onBack={vi.fn()} />)

    await screen.findByText('Campaign authorization')
    fireEvent.change(screen.getByLabelText('Operator ID'), { target: { value: 'operator-1' } })
    fireEvent.change(screen.getByLabelText(/Type ASSESS/), { target: { value: `ASSESS ${target.name}` } })
    fireEvent.click(screen.getByRole('button', { name: 'Start all 2 scans' }))

    await waitFor(() => expect(screen.getByText('2/2 completed')).toBeInTheDocument())
    expect(lease).toHaveBeenCalledTimes(2)
    expect(lease.mock.calls.map(([body]) => body.operator_profile_id)).toEqual(['DISCOVERY', 'EXPOSURE'])
  })
})
