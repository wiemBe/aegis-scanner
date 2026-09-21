import { useState } from 'react'
import type { ReactNode } from 'react'

// The Phase 1.5 ZAP Active view. Everything it renders comes from the controller's redacted
// projection: digests, counts, bounded labels and verifier verdicts. The browser is never sent the
// lease-signing secret, a raw lease token, a raw attack payload, a response body, cookie or
// authorization data, or any ground-truth answer key — there is deliberately no type here that
// could hold one.

export type ZapActiveCountersign = {
  valid: boolean
  code: string
  record_id?: string | null
  countersigned_on?: string | null
  countersigned_by?: string | null
  rule_id?: number | null
  rule_name?: string | null
  strength?: string | null
  threshold?: string | null
  environment?: string | null
  manifest_sha256?: string | null
  scope_statement?: string | null
  accepted_residual_risk?: string | null
  countersigned_add_on_ids?: string[]
}

export type ZapActiveConfig = {
  enabled: boolean
  profile_id: string
  capability_id: string
  activity: string
  passive_profile_id: string
  environment: string
  confirmation_phrase: string
  manifest_version: string
  manifest_digest: string
  engine_version: string
  image_index_digest: string
  admitted_rule: { plugin_id: number; name: string; strength: string; threshold: string; cwe_id: number; quality: string }
  neutralised_dependency_ids: string[]
  countersign: ZapActiveCountersign
  scenarios: { scenario: string; title: string }[]
  warnings: { severity: string; zero_alerts: string; browser_execution: string }
}

export type ZapActivePreflight = {
  ready: boolean
  blockers: string[]
  countersign: ZapActiveCountersign
  lease_secret_configured: boolean
  runner: ZapActiveRunner | null
  lease_status: ZapActiveLeaseStatus
}

type ZapActiveRunner = {
  ready: boolean
  runner_version: string
  failure_codes: string[]
  zap_version: string | null
  image_index_digest: string | null
  add_on_inventory_digest: string | null
  manifest_digest: string
  admitted_rule_ids: number[]
  addonlist_verified: boolean
  java_verified: boolean
  neutralised_dependency_ids: string[]
  guard: { reachable: boolean; guard_version: string | null; state: string | null; allowed_origins: string[] }
}

type ZapActiveLeaseStatus = {
  admission_reachable: boolean
  state_root_owned?: boolean
  armed?: { lease_id: string; state: string; expires_at: string } | null
  armed_total?: number
  consumed_total?: number
  revoked_total?: number
  rejected_total?: number
  restart_revoked_total?: number
}

export type ZapActiveAlert = {
  plugin_id: number
  rule_name: string
  method: string
  path: string
  param: string
  claimed_risk: string
  claimed_confidence: string
  attack_class: string
  attack_sha256: string
  evidence_sha256: string
  record_digest: string
  state: 'TOOL_REPORTED' | 'AEGIS_CORRELATED' | 'VERIFIED' | 'REVIEW_REQUIRED' | 'REJECTED'
  reason: string
}

export type ZapActiveSession = {
  session_id: string
  state: 'IDLE' | 'ARMED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'STOPPED'
  profile_id: string
  activity: string
  capability_id: string
  scenario: string
  operator_id: string
  scan_id: string
  execution_id: string
  created_at: string
  updated_at: string
  environment: string
  target: { method: string; query_param: string } | null
  rule: { plugin_id: number; strength: string; threshold: string } | null
  provenance: { manifest_digest: string | null; add_on_inventory_digest: string | null; projection_digest: string | null; allowlist_digest: string | null; source_sha256: string | null; runner: ZapActiveRunner | null }
  countersign: ZapActiveCountersign
  lease: Record<string, unknown> | null
  armed_lease: Record<string, unknown> | null
  lease_status: ZapActiveLeaseStatus | null
  budgets: { max_requests: number; time_budget_ms: number; delay_ms: number; max_alerts: number; max_report_bytes: number } | null
  traffic: { received: number; forwarded: number; blocked: number; blocked_reasons: (string | number)[][]; redirects: number; budget_exceeded: boolean } | null
  progress: { stage: string; percent: number; checkpoints?: { name: string; reached: boolean }[]; coverage_complete?: boolean; exit_class?: string; error_code?: string | null; duration_ms?: number; report_sha256?: string | null; stdout_sha256?: string | null }
  alerts: ZapActiveAlert[]
  alert_states: Record<string, number>
  verification: { verifier_version: string; status: string; summary: string; marker: string; evidence_names: string[] } | null
  verifier_probes: { name: string; role: string; status_code: number | null; content_class: string; body_bytes: number; body_sha256: string | null; variant_marker_ok: boolean; reflection: string }[]
  cleanup: { reset_before: boolean; reset_after: boolean; session_destroyed: boolean; lease_revoked: boolean }
  stop_steps: Record<string, boolean>
  terminal_reason: string
  verdict: { outcome: string; owner: string; detail: string }
  evidence_digest: string
  warnings: { severity: string; zero_alerts: string; browser_execution: string }
}

const ALERT_STATES = ['TOOL_REPORTED', 'AEGIS_CORRELATED', 'VERIFIED', 'REVIEW_REQUIRED', 'REJECTED'] as const

const short = (value: string | null | undefined, size = 18) =>
  value ? (value.length > size ? `${value.slice(0, size)}…` : value) : '—'
const yesNo = (value: boolean | null | undefined) => (value === undefined || value === null ? '—' : value ? 'YES' : 'NO')
const when = (value: string | null | undefined) =>
  value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value)) : '—'

function Tag({ children, tone = 'neutral' }: { children: ReactNode; tone?: string }) {
  return <span className={`badge ${tone}`}>{children}</span>
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return <div><dt>{label}</dt><dd>{children}</dd></div>
}

export function ZapActiveView({ config, preflight, session, busy, authRequired = false, onLogin, onActivate, onRun, onStop, onRefresh }: {
  config?: ZapActiveConfig
  preflight?: ZapActivePreflight
  session?: ZapActiveSession
  busy: boolean
  authRequired?: boolean
  onLogin?: (bootstrapSecret: string) => void
  onActivate: (scenario: string, phrase: string) => void
  onRun: () => void
  onStop: () => void
  onRefresh: () => void
}) {
  const [ceremony, setCeremony] = useState(false)
  if (!config) {
    if (authRequired && onLogin) return <ZapActiveLogin busy={busy} onLogin={onLogin} />
    return <div className="empty-state"><div className="empty-mark">A</div><h3>ZAP Active unavailable</h3><p>The controller did not return an active-scan configuration.</p></div>
  }
  const running = session?.state === 'RUNNING'
  const armed = session?.state === 'ARMED'
  const countersign = session?.countersign ?? config.countersign
  const runner = session?.provenance.runner ?? preflight?.runner ?? null
  const leaseStatus = session?.lease_status ?? preflight?.lease_status ?? null
  const lease = (session?.lease ?? {}) as Record<string, string | number | null>
  const verdict = session?.verdict

  return <div className="view-stack zap-active">
    <section className="panel zap-active-head">
      <div>
        <p className="eyebrow">CONTROLLED ACTIVE SCANNING · SENDS PAYLOADS TO THE TARGET</p>
        <h2>ZAP Active — reflected XSS</h2>
        <p className="muted">One controller-owned rule, one anonymous read-only synthetic endpoint, one single-use lease.</p>
      </div>
      <div className="zap-active-status">
        <Tag tone="danger">ACTIVE</Tag>
        <Tag tone="neutral">PASSIVE PROFILE: {config.passive_profile_id}</Tag>
        <Tag tone="scope">{config.environment}</Tag>
        <Tag tone={session ? (session.state === 'STOPPED' ? 'danger' : session.state === 'COMPLETED' ? 'good' : 'blue') : 'neutral'}>{session?.state ?? 'IDLE'}</Tag>
        <button className="secondary" onClick={onRefresh}>Refresh</button>
      </div>
    </section>

    {(running || armed) && <section className="zap-active-stop-strip" aria-label="Emergency stop">
      <div><strong>{running ? 'ACTIVE SCAN IN FLIGHT' : 'LEASE ARMED'}</strong>
        <span>{running ? 'Payloads are being sent to the synthetic target.' : 'A single-use lease is armed and awaiting execution.'}</span></div>
      <button className="zap-active-stop" onClick={onStop}>STOP ACTIVE SCAN</button>
    </section>}

    <section className="panel zap-active-warnings" aria-label="Interpretation warnings">
      <p><strong>Scanner severity is not Aegis severity.</strong> {config.warnings.severity}</p>
      <p><strong>Zero ZAP alerts alone is not a PASS.</strong> {config.warnings.zero_alerts}</p>
      <p><strong>No browser execution is claimed.</strong> {config.warnings.browser_execution}</p>
    </section>

    <div className="two-col">
      <section className="panel"><div className="section-head"><h3>Profile, target and admitted rule</h3><Tag tone={config.enabled ? 'good' : 'neutral'}>{config.enabled ? 'ADAPTER ENABLED' : 'ADAPTER DISABLED'}</Tag></div>
        <dl className="detail-list">
          <Row label="Profile">{config.profile_id} · {config.activity}</Row>
          <Row label="Capability">{config.capability_id}</Row>
          <Row label="Environment classification">{config.environment}</Row>
          <Row label="Target scope"><span className="mono">{session?.target ? `${session.target.method} controller-bound query parameter ${session.target.query_param}` : 'Controller-bound synthetic scenario'}</span></Row>
          <Row label="Admitted active rule">{config.admitted_rule.plugin_id} · {config.admitted_rule.name}</Row>
          <Row label="Strength / threshold">{config.admitted_rule.strength} / {config.admitted_rule.threshold} · CWE-{config.admitted_rule.cwe_id} · {config.admitted_rule.quality}</Row>
          <Row label="Neutralised dependencies">{config.neutralised_dependency_ids.join(', ') || 'none'}</Row>
        </dl>
      </section>

      <section className="panel"><div className="section-head"><h3>Manifest, image and countersign</h3><Tag tone={countersign.valid ? 'good' : 'danger'}>{countersign.valid ? 'COUNTERSIGNED' : `INVALID · ${countersign.code}`}</Tag></div>
        <dl className="detail-list">
          <Row label="Manifest"><span className="mono">v{config.manifest_version} · {short(config.manifest_digest, 22)}</span></Row>
          <Row label="Engine image"><span className="mono">ZAP {config.engine_version} · {short(config.image_index_digest, 22)}</span></Row>
          <Row label="Add-on inventory"><span className="mono">{short(runner?.add_on_inventory_digest, 22)}</span></Row>
          <Row label="Countersigned by">{countersign.countersigned_by ?? '—'} · {countersign.countersigned_on ?? '—'}</Row>
          <Row label="Countersigned record"><span className="mono">{countersign.record_id ?? '—'}</span></Row>
          <Row label="Countersigned scope">{countersign.scope_statement ?? '—'}</Row>
          <Row label="Accepted residual risk">{countersign.accepted_residual_risk ?? '—'}</Row>
        </dl>
      </section>
    </div>

    <div className="two-col">
      <section className="panel"><div className="section-head"><h3>Preflight</h3><Tag tone={preflight?.ready ? 'good' : 'warning'}>{preflight?.ready ? 'READY' : 'NOT READY'}</Tag></div>
        {preflight?.blockers.length ? <ul className="zap-active-blockers">{preflight.blockers.map((item) => <li key={item}><Tag tone="warning">{item}</Tag></li>)}</ul> : <p className="muted">No blockers. Activation requires the exact confirmation phrase.</p>}
        <dl className="detail-list compact">
          <Row label="Lease-signing secret configured">{yesNo(preflight?.lease_secret_configured)}</Row>
          <Row label="Lease admission reachable">{yesNo(leaseStatus?.admission_reachable)}</Row>
          <Row label="Admission state root-owned">{yesNo(leaseStatus?.state_root_owned)}</Row>
        </dl>
      </section>

      <section className="panel"><div className="section-head"><h3>Runner and scope-guard attestation</h3><Tag tone={runner?.ready ? 'good' : 'warning'}>{runner?.ready ? 'ATTESTED' : 'NOT ATTESTED'}</Tag></div>
        <dl className="detail-list compact">
          <Row label="Runner">{runner?.runner_version ?? '—'} · ZAP {runner?.zap_version ?? '—'}</Row>
          <Row label="Runner manifest digest"><span className="mono">{short(runner?.manifest_digest, 22)}</span></Row>
          <Row label="Admitted rule ids">{runner?.admitted_rule_ids.join(', ') ?? '—'}</Row>
          <Row label="Add-on list / JVM verified">{yesNo(runner?.addonlist_verified)} / {yesNo(runner?.java_verified)}</Row>
          <Row label="Scope guard">{runner?.guard.guard_version ?? '—'} · {runner?.guard.state ?? '—'} · {runner?.guard.reachable ? 'reachable' : 'not attested'}</Row>
          <Row label="Guard allowed origins"><span className="mono">{runner?.guard.allowed_origins.join(', ') ?? '—'}</span></Row>
          <Row label="Failure codes">{runner?.failure_codes.join(', ') || 'none'}</Row>
        </dl>
      </section>
    </div>

    <section className="panel"><div className="section-head"><h3>Single-use lease</h3><Tag tone={lease.state === 'COMPLETED' ? 'good' : lease.state === 'REVOKED' ? 'danger' : lease.state ? 'blue' : 'neutral'}>{String(lease.state ?? 'NONE')}</Tag></div>
      <dl className="detail-list compact">
        <Row label="Lease id"><span className="mono">{String(lease.lease_id ?? '—')}</span></Row>
        <Row label="Expires">{when(lease.expires_at as string | undefined)}</Row>
        <Row label="Lifetime">{lease.lifetime_seconds ? `${lease.lifetime_seconds}s (max 900s)` : '—'}</Row>
        <Row label="Audience"><span className="mono">{String(lease.audience ?? '—')}</span></Row>
        <Row label="Budget id"><span className="mono">{String(lease.budget_id ?? '—')}</span></Row>
        <Row label="Bound projection digest"><span className="mono">{short(lease.projection_digest as string | undefined, 22)}</span></Row>
        <Row label="Bound allowlist digest"><span className="mono">{short(lease.allowlist_digest as string | undefined, 22)}</span></Row>
        <Row label="Runner armed / consumed / revoked">{leaseStatus?.armed_total ?? 0} / {leaseStatus?.consumed_total ?? 0} / {leaseStatus?.revoked_total ?? 0}</Row>
        <Row label="Runner rejections">{leaseStatus?.rejected_total ?? 0}</Row>
      </dl>
      <p className="responsibility-note">The lease token itself is never sent to this browser. Only bindings, state and expiry are shown.</p>
    </section>

    <div className="two-col">
      <section className="panel"><div className="section-head"><h3>Budgets</h3><Tag tone="scope">HARD CAPPED</Tag></div>
        <dl className="detail-list compact">
          <Row label="Request budget">{session?.budgets?.max_requests ?? '—'} requests</Row>
          <Row label="Time budget">{session?.budgets ? `${Math.round(session.budgets.time_budget_ms / 1000)}s` : '—'}</Row>
          <Row label="Inter-request delay">{session?.budgets ? `${session.budgets.delay_ms}ms` : '—'}</Row>
          <Row label="Alert / report caps">{session?.budgets ? `${session.budgets.max_alerts} alerts · ${session.budgets.max_report_bytes} bytes` : '—'}</Row>
        </dl>
      </section>
      <section className="panel"><div className="section-head"><h3>Observed traffic (scope guard, independent of ZAP)</h3><Tag tone={session?.traffic?.blocked ? 'warning' : 'neutral'}>{session?.traffic?.blocked ?? 0} refused</Tag></div>
        <dl className="detail-list compact">
          <Row label="Observed / forwarded">{session?.traffic?.received ?? '—'} / {session?.traffic?.forwarded ?? '—'}</Row>
          <Row label="Refused (never reached target)">{session?.traffic?.blocked ?? '—'}</Row>
          <Row label="Refusal reasons">{session?.traffic?.blocked_reasons.map((pair) => pair.join('×')).join(', ') || 'none'}</Row>
          <Row label="Redirects observed">{session?.traffic?.redirects ?? '—'}</Row>
          <Row label="Budget exceeded">{yesNo(session?.traffic?.budget_exceeded)}</Row>
        </dl>
      </section>
    </div>

    <section className="panel"><div className="section-head"><h3>Scan progress</h3><Tag tone={session?.progress.coverage_complete ? 'good' : 'warning'}>{session?.progress.coverage_complete ? 'COVERAGE COMPLETE' : 'COVERAGE INCOMPLETE'}</Tag></div>
      <div className="meter"><div className="meter-copy"><span>{session?.progress.stage.replaceAll('_', ' ') ?? 'NOT STARTED'}</span><strong>{session?.progress.percent ?? 0}%</strong></div><div className="meter-track"><i style={{ width: `${session?.progress.percent ?? 0}%` }} /></div></div>
      <div className="workflow">{(session?.progress.checkpoints ?? []).map((point, index) => <div className={`workflow-step ${point.reached ? 'reached' : ''}`} key={point.name}><i>{String(index + 1).padStart(2, '0')}</i><span>{point.name.replaceAll('_', ' ')}</span></div>)}</div>
      <dl className="detail-list compact">
        <Row label="Exit class">{session?.progress.exit_class ?? '—'}{session?.progress.error_code ? ` · ${session.progress.error_code}` : ''}</Row>
        <Row label="Duration">{session?.progress.duration_ms ? `${session.progress.duration_ms}ms` : '—'}</Row>
        <Row label="Report / stdout digest"><span className="mono">{short(session?.progress.report_sha256, 16)} / {short(session?.progress.stdout_sha256, 16)}</span></Row>
      </dl>
    </section>

    <section className="panel"><div className="section-head"><div><p className="eyebrow">TOOL CLAIM ≠ AEGIS CONCLUSION</p><h3>Alert lifecycle</h3></div><Tag tone="scope">VERIFIER OWNS PROMOTION</Tag></div>
      <div className="zap-active-lifecycle">{ALERT_STATES.map((state) => <div className={`zap-active-lifecycle-cell ${state.toLowerCase()}`} key={state}><span>{state.replaceAll('_', ' ')}</span><strong>{session?.alert_states?.[state] ?? 0}</strong></div>)}</div>
      {session?.alerts.length ? <div className="table-scroll"><table><thead><tr><th>State</th><th>Rule</th><th>Operation</th><th>Param</th><th>Tool claim (untrusted)</th><th>Attack class</th><th>Attack digest</th><th>Reason</th></tr></thead><tbody>
        {session.alerts.map((alert) => <tr key={alert.record_digest}>
          <td><Tag tone={alert.state === 'VERIFIED' ? 'good' : alert.state === 'REJECTED' ? 'neutral' : alert.state === 'REVIEW_REQUIRED' ? 'warning' : 'blue'}>{alert.state.replaceAll('_', ' ')}</Tag></td>
          <td>{alert.plugin_id} · {alert.rule_name}</td>
          <td className="mono">{alert.method} {alert.path}</td>
          <td className="mono">{alert.param}</td>
          <td>risk {alert.claimed_risk} · confidence {alert.claimed_confidence}</td>
          <td>{alert.attack_class}</td>
          <td className="mono">{short(alert.attack_sha256, 14)}</td>
          <td>{alert.reason}</td>
        </tr>)}
      </tbody></table></div> : <p className="muted">No tool-reported alert. That is not itself a result.</p>}
      <p className="redaction-note">Raw attack payloads and response bodies are never carried: an alert keeps a structural class and a digest only.</p>
    </section>

    <div className="two-col">
      <section className="panel"><div className="section-head"><h3>Independent Aegis verifier</h3><Tag tone={session?.verification?.status === 'CONFIRMED' ? 'danger' : session?.verification?.status === 'PASS' ? 'good' : 'warning'}>{session?.verification?.status ?? 'NOT RUN'}</Tag></div>
        <dl className="detail-list compact">
          <Row label="Verifier">{session?.verification?.verifier_version ?? '—'}</Row>
          <Row label="Conclusion">{session?.verification?.summary ?? '—'}</Row>
          <Row label="Fresh marker used">{yesNo(Boolean(session?.verification?.marker))}</Row>
        </dl>
        {session?.verifier_probes.length ? <div className="table-scroll"><table><thead><tr><th>Probe</th><th>Role</th><th>Status</th><th>Content</th><th>Variant marker</th><th>Reflection</th><th>Body digest</th></tr></thead><tbody>
          {session.verifier_probes.map((probe) => <tr key={probe.name}><td className="mono">{short(probe.name, 20)}</td><td>{probe.role}</td><td>{probe.status_code ?? '—'}</td><td>{probe.content_class}</td><td>{yesNo(probe.variant_marker_ok)}</td><td>{probe.reflection}</td><td className="mono">{short(probe.body_sha256, 14)}</td></tr>)}
        </tbody></table></div> : null}
      </section>

      <section className="panel"><div className="section-head"><h3>Outcome, cleanup and reset</h3><Tag tone={verdict?.outcome === 'PASS' ? 'good' : verdict?.outcome === 'VERIFIED_VULNERABLE' ? 'danger' : 'warning'}>{verdict?.outcome ?? 'NOT RUN'}</Tag></div>
        <dl className="detail-list compact">
          <Row label="Verdict owner">{verdict?.owner ?? '—'}</Row>
          <Row label="Detail">{verdict?.detail ?? '—'}</Row>
          <Row label="Terminal reason">{session?.terminal_reason || '—'}</Row>
          <Row label="Target reset before / after">{yesNo(session?.cleanup.reset_before)} / {yesNo(session?.cleanup.reset_after)}</Row>
          <Row label="Runner session destroyed">{yesNo(session?.cleanup.session_destroyed)}</Row>
          <Row label="Lease revoked after execution">{yesNo(session?.cleanup.lease_revoked)}</Row>
          <Row label="Emergency-stop steps">{Object.keys(session?.stop_steps ?? {}).length ? Object.entries(session!.stop_steps).map(([key, value]) => `${key}=${value ? 'OK' : 'NO'}`).join(' · ') : '—'}</Row>
          <Row label="Evidence digest"><span className="mono">{short(session?.evidence_digest, 22)}</span></Row>
        </dl>
      </section>
    </div>

    <section className="panel zap-active-actions">
      <div><h3>Activation</h3><p className="muted">Active scanning is never implied by the passive capability. It requires this ceremony, a fresh single-use lease and a valid operator countersign.</p></div>
      <div className="zap-active-buttons">
        <button className="beast-launch" disabled={busy || !preflight?.ready || armed || running} onClick={() => setCeremony(true)}>ACTIVATE ACTIVE SCAN</button>
        <button className="secondary" disabled={busy || !armed} onClick={onRun}>Execute armed lease</button>
      </div>
    </section>

    {ceremony && <ZapActiveCeremony config={config} busy={busy} onClose={() => setCeremony(false)} onActivate={(variant, phrase) => { setCeremony(false); onActivate(variant, phrase) }} />}
  </div>
}

function ZapActiveLogin({ busy, onLogin }: { busy: boolean; onLogin: (bootstrapSecret: string) => void }) {
  const [bootstrapSecret, setBootstrapSecret] = useState('')
  return <section className="panel zap-active-login" aria-label="Operator authentication">
    <p className="eyebrow">OPERATOR AUTHENTICATION REQUIRED</p>
    <h2>ZAP Active controls are server-side protected</h2>
    <p className="muted">Enter the operator bootstrap secret to establish a short-lived HttpOnly session. The value is used once and is not retained by the console.</p>
    <label><span>Operator bootstrap secret</span><input type="password" autoComplete="current-password" value={bootstrapSecret} onChange={(event) => setBootstrapSecret(event.target.value)} /></label>
    <button className="beast-launch" disabled={busy || bootstrapSecret.length < 32} onClick={() => { onLogin(bootstrapSecret); setBootstrapSecret('') }}>Authenticate operator session</button>
  </section>
}

function ZapActiveCeremony({ config, busy, onClose, onActivate }: {
  config: ZapActiveConfig
  busy: boolean
  onClose: () => void
  onActivate: (scenario: string, phrase: string) => void
}) {
  const [phrase, setPhrase] = useState('')
  const [scenario, setScenario] = useState(config.scenarios[0]?.scenario ?? 'scenario-a')
  const expected = config.confirmation_phrase
  return <div className="beast-modal-scrim" role="presentation"><section className="beast-modal" role="dialog" aria-modal="true" aria-label="ZAP Active activation ceremony">
    <header><div><p className="eyebrow">CONTROLLED ACTIVE SCAN · SYNTHETIC LAB ONLY</p><h2>ZAP Active activation</h2><span>One rule, one endpoint, one single-use lease, one execution.</span></div><button aria-label="Close activation ceremony" onClick={onClose}>×</button></header>
    <div className="beast-warning">This sends attack payloads to the target on the projected query parameter. Scanner severity is not Aegis severity, and zero alerts is not a PASS.</div>
    <div className="beast-preflight-grid">
      <dl className="detail-list">
        <Row label="Profile">{config.profile_id}</Row>
        <Row label="Environment">{config.environment}</Row>
        <Row label="Target">Controller-bound anonymous synthetic-lab endpoint</Row>
        <Row label="Admitted rule">{config.admitted_rule.plugin_id} · {config.admitted_rule.name}</Row>
        <Row label="Strength / threshold">{config.admitted_rule.strength} / {config.admitted_rule.threshold}</Row>
        <Row label="Manifest digest"><span className="mono">{short(config.manifest_digest, 26)}</span></Row>
        <Row label="Operator countersign">{config.countersign.valid ? `VALID · ${config.countersign.record_id}` : `INVALID · ${config.countersign.code}`}</Row>
      </dl>
      <div>
        <h3>What this lease cannot do</h3>
        <p className="muted">It cannot select another rule, another target, another profile, another environment or another manifest digest. It expires within 15 minutes, is consumed by exactly one execution, and is revoked on completion, failure or stop.</p>
        <h3>Countersigned scope</h3>
        <p className="muted">{config.countersign.scope_statement ?? '—'}</p>
      </div>
    </div>
    <label><span>Scenario</span><select value={scenario} onChange={(event) => setScenario(event.target.value)}>{config.scenarios.map((item) => <option value={item.scenario} key={item.scenario}>{item.title}</option>)}</select></label>
    <label><span>Type <code>{expected}</code> to issue one single-use lease</span><input autoComplete="off" value={phrase} onChange={(event) => setPhrase(event.target.value)} /></label>
    <footer><button className="secondary" onClick={onClose}>Cancel</button><button className="beast-launch" disabled={busy || phrase !== expected || !config.countersign.valid} onClick={() => onActivate(scenario, phrase)}>{busy ? 'Activating…' : 'Issue lease and arm'}</button></footer>
  </section></div>
}
