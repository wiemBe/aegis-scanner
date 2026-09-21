import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ZapActiveConfig, ZapActivePreflight, ZapActiveSession } from './ZapActive'
import { ZapActiveView } from './ZapActive'

const PHRASE = 'ACTIVATE SYNTHETIC-LAB REFLECTED-XSS ACTIVE SCAN'

const config: ZapActiveConfig = {
  enabled: true,
  profile_id: 'ZAP_LAB_ACTIVE_REFLECTED_XSS_V1',
  capability_id: 'zap_active_reflected_xss_v1',
  activity: 'ACTIVE',
  passive_profile_id: 'ZAP_LAB_PASSIVE_V1',
  environment: 'SYNTHETIC_LAB',
  confirmation_phrase: PHRASE,
  manifest_version: '1.5.0',
  manifest_digest: '0'.repeat(64),
  engine_version: '2.17.0',
  image_index_digest: 'sha256:781a2bdaea47',
  admitted_rule: { plugin_id: 40012, name: 'Cross Site Scripting (Reflected)', strength: 'LOW', threshold: 'MEDIUM', cwe_id: 79, quality: 'release' },
  neutralised_dependency_ids: ['database', 'oast'],
  countersign: { valid: true, code: 'VALID', record_id: 'countersign-zap-active-reflected-xss-v1', countersigned_on: '2026-09-21', countersigned_by: 'OPERATOR', rule_id: 40012, rule_name: 'Cross Site Scripting (Reflected)', strength: 'LOW', threshold: 'MEDIUM', environment: 'SYNTHETIC_LAB', manifest_sha256: '0'.repeat(64), scope_statement: 'One anonymous, read-only reflected-XSS capability against the resettable synthetic lab only.', accepted_residual_risk: 'Neutralised oast/database chain only.', countersigned_add_on_ids: ['ascanrules', 'database', 'oast'] },
  scenarios: [{ scenario: 'scenario-a', title: 'Controlled synthetic scenario A' }],
  warnings: { severity: 'Scanner severity is not Aegis severity.', zero_alerts: 'Zero ZAP alerts is not a PASS.', browser_execution: 'No browser executes the payload.' },
}

const runner = {
  ready: true, runner_version: 'zap-active-runner/1.5.0', failure_codes: [], zap_version: '2.17.0',
  image_index_digest: 'sha256:781a2b', add_on_inventory_digest: 'a'.repeat(64), manifest_digest: '0'.repeat(64),
  admitted_rule_ids: [40012], addonlist_verified: true, java_verified: true, neutralised_dependency_ids: ['database', 'oast'],
  guard: { reachable: true, guard_version: 'zap-scope-guard/1.3.0', state: 'IDLE', allowed_origins: ['http://lab-api:8001'] },
}

const preflight: ZapActivePreflight = {
  ready: true, blockers: [], countersign: config.countersign, lease_secret_configured: true, runner,
  lease_status: { admission_reachable: true, state_root_owned: true, armed: null, armed_total: 1, consumed_total: 1, revoked_total: 1, rejected_total: 0, restart_revoked_total: 0 },
}

const session = (over: Partial<ZapActiveSession> = {}): ZapActiveSession => ({
  session_id: 'session-abc123abc123', state: 'COMPLETED', profile_id: config.profile_id, activity: 'ACTIVE',
  capability_id: config.capability_id, scenario: 'scenario-a', operator_id: 'local-operator',
  scan_id: 'scan-aaaaaaaaaaaa', execution_id: 'exec-aaaaaaaaaaaa',
  created_at: '2026-09-21T10:00:00Z', updated_at: '2026-09-21T10:02:00Z', environment: 'SYNTHETIC_LAB',
  target: { method: 'GET', query_param: 'q' },
  rule: { plugin_id: 40012, strength: 'low', threshold: 'medium' },
  provenance: { manifest_digest: '0'.repeat(64), add_on_inventory_digest: 'a'.repeat(64), projection_digest: 'b'.repeat(64), allowlist_digest: 'c'.repeat(64), source_sha256: 'd'.repeat(64), runner },
  countersign: config.countersign,
  lease: { lease_id: 'lease-abcdef0123456789', state: 'COMPLETED', expires_at: '2026-09-21T10:15:00Z', lifetime_seconds: 900, audience: 'aegis-zap-active-runner', budget_id: 'budget-abcdef012345', projection_digest: 'b'.repeat(64), allowlist_digest: 'c'.repeat(64) },
  armed_lease: null, lease_status: preflight.lease_status,
  budgets: { max_requests: 200, time_budget_ms: 300000, delay_ms: 250, max_alerts: 8, max_report_bytes: 131072 },
  traffic: { received: 3, forwarded: 3, blocked: 0, blocked_reasons: [], redirects: 0, budget_exceeded: false },
  progress: { stage: 'REPORT_GENERATED', percent: 100, checkpoints: [{ name: 'PLAN_VALIDATED', reached: true }], coverage_complete: true, exit_class: 'OK', error_code: null, duration_ms: 42000, report_sha256: 'e'.repeat(64), stdout_sha256: 'f'.repeat(64) },
  alerts: [{ plugin_id: 40012, rule_name: 'Cross Site Scripting (Reflected)', method: 'GET', path: '/lab/zap-active/vulnerable/search', param: 'q', claimed_risk: 'high', claimed_confidence: 'medium', attack_class: 'SCRIPT_ELEMENT', attack_sha256: '1'.repeat(64), evidence_sha256: '2'.repeat(64), record_digest: '3'.repeat(64), state: 'VERIFIED', reason: 'VERIFIER_CONFIRMED_RAW_EXECUTABLE' }],
  alert_states: { TOOL_REPORTED: 0, AEGIS_CORRELATED: 0, VERIFIED: 1, REVIEW_REQUIRED: 0, REJECTED: 0 },
  verification: { verifier_version: 'aegis-zap-xss-verifier/1.5.0', status: 'CONFIRMED', summary: 'Fresh marker reached an executable HTML script context unescaped.', marker: 'AEGIS0123', evidence_names: [] },
  verifier_probes: [{ name: 'scan-aaaaaaaaaaaa-verify-xss', role: 'XSS_PROBE', status_code: 200, content_class: 'HTML', body_bytes: 300, body_sha256: '4'.repeat(64), variant_marker_ok: true, reflection: 'RAW_EXECUTABLE' }],
  cleanup: { reset_before: true, reset_after: true, session_destroyed: true, lease_revoked: true },
  stop_steps: {}, terminal_reason: 'COMPLETE',
  verdict: { outcome: 'VERIFIED_VULNERABLE', owner: 'AEGIS_VERIFIER', detail: 'Verifier confirmed.' },
  evidence_digest: '5'.repeat(64),
  warnings: config.warnings,
  ...over,
})

const noop = () => { /* intentionally inert in these tests */ }
const view = (props: Partial<Parameters<typeof ZapActiveView>[0]> = {}) =>
  render(<ZapActiveView config={config} preflight={preflight} session={session()} busy={false}
    onActivate={noop} onRun={noop} onStop={noop} onRefresh={noop} {...props} />)

afterEach(() => cleanup())

describe('ZAP Active console view', () => {
  it('separates the ACTIVE profile from the passive profile and names the exact target and rule', () => {
    view()
    expect(screen.getByText('ACTIVE')).toBeInTheDocument()
    expect(screen.getByText('PASSIVE PROFILE: ZAP_LAB_PASSIVE_V1')).toBeInTheDocument()
    expect(screen.getAllByText('SYNTHETIC_LAB').length).toBeGreaterThan(0)
    expect(screen.getByText('GET controller-bound query parameter q')).toBeInTheDocument()
    expect(screen.getAllByText('40012 · Cross Site Scripting (Reflected)').length).toBeGreaterThan(0)
  })

  it('warns that scanner severity is not Aegis severity and that zero alerts is not a PASS', () => {
    view()
    expect(screen.getAllByText(/Scanner severity is not Aegis severity/).length).toBeGreaterThan(0)
    expect(screen.getByText(/Zero ZAP alerts alone is not a PASS/)).toBeInTheDocument()
    expect(screen.getByText(/No browser execution is claimed/)).toBeInTheDocument()
  })

  it('shows the operator countersign status and the manifest it is bound to', () => {
    view()
    expect(screen.getByText('COUNTERSIGNED')).toBeInTheDocument()
    expect(screen.getByText('countersign-zap-active-reflected-xss-v1')).toBeInTheDocument()
    expect(screen.getByText(/OPERATOR · 2026-09-21/)).toBeInTheDocument()
  })

  it('refuses activation while the countersign is invalid', () => {
    const invalid = { ...config, countersign: { valid: false, code: 'MANIFEST_DIGEST_MISMATCH' } }
    view({ config: invalid, session: session({ countersign: invalid.countersign }) })
    expect(screen.getByText('INVALID · MANIFEST_DIGEST_MISMATCH')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'ACTIVATE ACTIVE SCAN' }))
    expect(screen.getByRole('button', { name: 'Issue lease and arm' })).toBeDisabled()
  })

  it('requires the exact confirmation phrase before a lease can be issued', () => {
    const onActivate = vi.fn()
    view({ session: session({ state: 'IDLE' }), onActivate })
    fireEvent.click(screen.getByRole('button', { name: 'ACTIVATE ACTIVE SCAN' }))
    const dialog = screen.getByRole('dialog')
    const input = within(dialog).getByLabelText(/Type/)
    fireEvent.change(input, { target: { value: 'ACTIVATE SYNTHETIC-LAB REFLECTED-XSS ACTIVE SCA' } })
    expect(within(dialog).getByRole('button', { name: 'Issue lease and arm' })).toBeDisabled()
    fireEvent.change(input, { target: { value: PHRASE } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Issue lease and arm' }))
    expect(onActivate).toHaveBeenCalledWith('scenario-a', PHRASE)
  })

  it('offers a prominent stop control whenever a lease is armed or a scan is in flight', () => {
    const onStop = vi.fn()
    const { rerender } = view({ session: session({ state: 'RUNNING' }), onStop })
    fireEvent.click(screen.getByRole('button', { name: 'STOP ACTIVE SCAN' }))
    expect(onStop).toHaveBeenCalled()
    rerender(<ZapActiveView config={config} preflight={preflight} session={session({ state: 'COMPLETED' })} busy={false} onActivate={noop} onRun={noop} onStop={noop} onRefresh={noop} />)
    expect(screen.queryByRole('button', { name: 'STOP ACTIVE SCAN' })).toBeNull()
  })

  it('keeps TOOL_REPORTED, AEGIS_CORRELATED, VERIFIED, REVIEW_REQUIRED and REJECTED distinct', () => {
    view({ session: session({ alert_states: { TOOL_REPORTED: 1, AEGIS_CORRELATED: 2, VERIFIED: 3, REVIEW_REQUIRED: 4, REJECTED: 5 } }) })
    for (const label of ['TOOL REPORTED', 'AEGIS CORRELATED', 'VERIFIED', 'REVIEW REQUIRED', 'REJECTED']) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0)
    }
  })

  it('shows a correlated-but-unverified alert as REVIEW REQUIRED, never as verified', () => {
    view({ session: session({
      alerts: [{ ...session().alerts[0]!, state: 'REVIEW_REQUIRED' as const, reason: 'VERIFIER_INSUFFICIENT' }],
      alert_states: { TOOL_REPORTED: 0, AEGIS_CORRELATED: 0, VERIFIED: 0, REVIEW_REQUIRED: 1, REJECTED: 0 },
      verification: { verifier_version: 'v', status: 'INSUFFICIENT', summary: 'Ambiguous reflection.', marker: 'AEGIS1', evidence_names: [] },
      verdict: { outcome: 'REVIEW_REQUIRED', owner: 'AEGIS_VERIFIER', detail: 'Ambiguous reflection.' },
    }) })
    expect(screen.getByText('VERIFIER_INSUFFICIENT')).toBeInTheDocument()
    expect(screen.getAllByText('REVIEW REQUIRED').length).toBeGreaterThan(0)
  })

  it('reports budgets, guard-observed traffic and cleanup state', () => {
    view()
    expect(screen.getByText('200 requests')).toBeInTheDocument()
    expect(screen.getByText('3 / 3')).toBeInTheDocument()
    expect(screen.getByText('0 refused')).toBeInTheDocument()
    expect(screen.getByText('COVERAGE COMPLETE')).toBeInTheDocument()
    expect(screen.getAllByText('YES / YES').length).toBeGreaterThan(0)
  })

  it('never renders a lease token, a raw attack payload or a response body', () => {
    const { container } = view()
    const text = container.textContent ?? ''
    expect(text).not.toContain('AZL1.')
    expect(text).not.toContain('<script>')
    expect(text).not.toContain('Set-Cookie')
    expect(text).not.toContain('Authorization')
    expect(text).toContain('SCRIPT_ELEMENT')
  })

  it('surfaces preflight blockers instead of offering activation', async () => {
    view({ preflight: { ...preflight, ready: false, blockers: ['ADMISSION_UNREACHABLE', 'RUNNER_NOT_ATTESTED'] }, session: session({ state: 'IDLE' }) })
    expect(screen.getByText('ADMISSION_UNREACHABLE')).toBeInTheDocument()
    expect(screen.getByText('NOT READY')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: 'ACTIVATE ACTIVE SCAN' })).toBeDisabled())
  })

  it('shows a stopped run as STOPPED with its ordered stop steps', () => {
    view({ session: session({ state: 'STOPPED', terminal_reason: 'EMERGENCY_STOP', verdict: { outcome: 'STOPPED', owner: 'OPERATOR', detail: 'Emergency stop' }, stop_steps: { lease_revoked: true, guard_disarmed: true, engine_killed: true, marked_stopped: true } }) })
    expect(screen.getAllByText('STOPPED').length).toBeGreaterThan(0)
    expect(screen.getByText(/lease_revoked=OK · guard_disarmed=OK · engine_killed=OK/)).toBeInTheDocument()
  })
})
