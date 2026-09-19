import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'

type View = 'Mission Control' | 'Runs' | 'Findings' | 'Audit' | 'Evidence' | 'Integrations' | 'System Health'
type StreamState = 'CONNECTING' | 'LIVE' | 'STALE' | 'GAP'

type Run = {
  id: string
  status: string
  target_name: string
  scope: string
  planner: string
  mode: string
  model: string | null
  model_digest: string | null
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
  scope_badges: string[]
  engine?: string
  adapter_version?: string | null
  engine_kernel_version?: number | null
  lifecycle_counts?: Record<string, number>
  engine_job_rejections?: number
  tool_reported_count?: number
  verifier_confirmed_count?: number
}

type EngineReadiness = {
  engine: string
  name: string
  adapter_version: string | null
  configured: boolean
  reachable: boolean | null
  enabled: boolean
  authorized: boolean
  state: string
  detail: string
  profile_id: string | null
  environment: string | null
  isolation_boundary: string
  capabilities: Record<string, unknown>[]
  kernel_version: number
  provenance?: {
    pinned_engine_version?: string
    pinned_binary_sha256?: Record<string, string>
    attested_engine_version?: string | null
    attested_binary_sha256?: string | null
    template_set_id?: string
    manifest_version?: string
    manifest_digest?: string
    attested_manifest_digest?: string | null
    admitted_template_count?: number
    upstream_templates?: string
    signature_probe?: string | null
    last_health_check?: string | null
    latest_execution?: {
      scan_id?: string
      status?: string
      terminal_reason?: string | null
      http_connections?: number | null
      request_budget?: number | null
      matched?: number | null
      records?: number | null
      lifecycle_states?: string[]
      tool_reported?: number
      verifier_confirmed?: number
      completed_at?: string | null
    } | null
    responsibility?: string
  } | null
}

type LifecycleCard = {
  normalized_id: string
  engine: string
  adapter_version: string | null
  capability_id: string
  lifecycle_state: string
  ai_hypothesis: string
  controller_authorization: string
  engine_reported: string
  aegis_finding_id: string | null
  severity: string | null
  confidence: string | null
  provenance: string
  verifier_status: string | null
}

type ExecutionPolicy = {
  engine: string
  adapter_version: string | null
  engine_kernel_version: number | null
  execution_policy_version: number
  jobs_created: { engine: string; job_id: string; execution_id: string; status: string; observation_count: number; reported_finding_count: number }[]
  jobs_rejected: { engine: string; code: string; detail: string }[]
}

type EventRecord = {
  event_id: string
  sequence: number
  timestamp: string
  run_id: string
  scan_id: string
  finding_id: string | null
  retest_scan_id: string | null
  parent_event_id: string | null
  child_event_ids: string[]
  actor_type: 'OPERATOR' | 'AI_PLANNER' | 'CONTROLLER' | 'TOOL_RUNNER' | 'VERIFIER' | 'SYSTEM'
  event_type: string
  stage: string
  status: string
  engine: string
  summary: string
  evidence_refs: Record<string, unknown>[]
  redaction_status: string
  metadata: Record<string, unknown>
  integrity: { algorithm: string; digest: string }
}

type Evidence = {
  artifact_type: 'API_EVIDENCE_CARD' | 'NUCLEI_EXECUTION_CARD' | 'VERIFIER_PROBE_CARD'
  artifact_id: string
  scan_id: string
  method: string
  normalized_route: string
  principal_profile_name: string
  object_reference: string
  response_status: number | null
  response_size: number | null
  response_characteristics: { bounded: boolean; body_redacted: boolean }
  timestamp: string
  request_id: string
  evidence_hash: string
  control_probe_role: string
}

type Finding = {
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

type Integration = { name: string; engine: string; state: string; model?: string | null; digest?: string | null; provider?: string | null }

const NAV: View[] = ['Mission Control', 'Runs', 'Findings', 'Audit', 'Evidence', 'Integrations', 'System Health']
const WORKFLOW = ['PREFLIGHT', 'AI_HYPOTHESIS', 'CANDIDATE_VALIDATION', 'QUEUE_ADMISSION', 'REQUEST_COMPILATION', 'SAFETY_AUTHORIZATION', 'EXECUTION', 'VERIFICATION', 'FINDING', 'LINKED_RETEST', 'COMPLETE']

const api = async <T,>(path: string): Promise<T> => {
  const response = await fetch(path, { headers: { Accept: 'application/json' } })
  if (!response.ok) throw new Error(`Request failed (${response.status})`)
  return response.json() as Promise<T>
}

const auditHistory = async (): Promise<EventRecord[]> => {
  const hydrated: EventRecord[] = []
  let cursor = 0
  for (let page = 0; page < 5; page += 1) {
    const result = await api<{ items: EventRecord[]; next_cursor: number | null }>(
      `/api/console/audit?limit=100&cursor=${cursor}`,
    )
    hydrated.push(...result.items)
    if (typeof result.next_cursor !== 'number' || result.next_cursor <= cursor) break
    cursor = result.next_cursor
  }
  return hydrated
}

const short = (value: string | null | undefined, size = 16) => value ? (value.length > size ? `${value.slice(0, size)}…` : value) : '—'
const when = (value: string | null | undefined) => value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value)) : '—'
const elapsed = (run?: Run) => {
  if (!run) return '—'
  const end = run.completed_at ? new Date(run.completed_at).getTime() : Date.now()
  const seconds = Math.max(0, Math.round((end - new Date(run.created_at).getTime()) / 1000))
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`
}

function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: string }) {
  return <span className={`badge ${tone}`}>{children}</span>
}

function ScopeBadges() {
  return <div className="scope-badges" aria-label="Permanent scope labels">
    {['SYNTHETIC LAB', 'LOCAL LLM', 'READ-ONLY', 'AUTHORIZED TARGET'].map((label) => <Badge key={label} tone="scope">{label}</Badge>)}
  </div>
}

function Meter({ value, maximum, label }: { value: number; maximum: number; label: string }) {
  const percent = Math.min(100, Math.round((value / Math.max(maximum, 1)) * 100))
  return <div className="meter"><div className="meter-copy"><span>{label}</span><strong>{value.toLocaleString()} / {maximum.toLocaleString()}</strong></div><div className="meter-track"><i style={{ width: `${percent}%` }} /></div></div>
}

function Empty({ title, copy }: { title: string; copy: string }) {
  return <div className="empty-state"><div className="empty-mark">A</div><h3>{title}</h3><p>{copy}</p></div>
}

function Loading() { return <div className="loading"><i /><span>Loading verified local records…</span></div> }

function MissionControl({ run, events, onOpenRun, streamState }: { run?: Run; events: EventRecord[]; onOpenRun: (id: string) => void; streamState: StreamState }) {
  if (!run) return <Empty title="No scan records yet" copy="Start an authorized synthetic scan from the engineering dashboard. Mission Control will hydrate its persisted audit trail here." />
  const runEvents = events.filter((item) => item.scan_id === run.id)
  const latest = runEvents.at(-1)
  const currentStage = latest?.stage ?? (run.completed_at ? 'COMPLETE' : 'PREFLIGHT')
  return <div className="view-stack">
    <section className="mission-head panel">
      <div><p className="eyebrow">LIVE OPERATIONAL OVERVIEW</p><h2>{run.target_name}</h2><p className="muted mono">{run.id}</p></div>
      <div className="mission-status"><Badge tone={run.status === 'FAIL' ? 'danger' : run.status === 'PASS' ? 'good' : 'blue'}>{run.status}</Badge><Badge tone={streamState === 'LIVE' ? 'good' : 'warning'}>{streamState}</Badge><button className="secondary" onClick={() => onOpenRun(run.id)}>Open replay</button></div>
    </section>
    <section className="stat-grid">
      <div className="stat panel"><span>CURRENT STAGE</span><strong>{currentStage.replaceAll('_', ' ')}</strong><small>Sequence {latest?.sequence ?? '—'}</small></div>
      <div className="stat panel"><span>MODEL / PROVIDER</span><strong>{run.model ?? run.planner}</strong><small>{run.mode}</small></div>
      <div className="stat panel"><span>ENGINE / ADAPTER</span><strong>{run.engine ?? 'AEGIS_NATIVE'}</strong><small>{run.adapter_version ?? 'aegis-native'} · policy v{run.execution_policy_version}</small></div>
      <div className="stat panel"><span>ELAPSED</span><strong>{elapsed(run)}</strong><small>Started {when(run.created_at)}</small></div>
    </section>
    <section className="panel workflow-panel">
      <div className="section-head"><div><p className="eyebrow">RESPONSIBILITY-AWARE WORKFLOW</p><h3>Live control path</h3></div><span className="muted">Planner contract v{run.planner_contract_version} · policy v{run.execution_policy_version}</span></div>
      <div className="workflow">
        {WORKFLOW.map((stage, index) => {
          const reached = runEvents.some((item) => item.stage === stage) || index <= WORKFLOW.indexOf(currentStage)
          const active = stage === currentStage
          const actor = stage === 'AI_HYPOTHESIS' ? 'ai' : stage === 'VERIFICATION' || stage === 'FINDING' ? 'verifier' : stage === 'SAFETY_AUTHORIZATION' ? 'safety' : 'controller'
          return <div className={`workflow-step ${reached ? 'reached' : ''} ${active ? 'active' : ''} ${actor}`} key={stage}><i>{String(index + 1).padStart(2, '0')}</i><span>{stage.replaceAll('_', ' ')}</span></div>
        })}
      </div>
      <div className="actor-legend"><span className="ai-dot">AI proposed</span><span className="controller-dot">Controller decided / sent</span><span className="verifier-dot">Verifier proved</span><span className="operator-dot">Operator initiated</span><span className="safety-dot">Safety decision</span></div>
    </section>
    <div className="two-col">
      <section className="panel"><div className="section-head"><h3>Bounded resources</h3><Badge tone="scope">FAIL CLOSED</Badge></div>
        <Meter label="Target requests" value={run.usage.requests} maximum={run.budgets.target_requests} />
        <Meter label="Model calls" value={run.usage.model_calls} maximum={run.budgets.model_calls} />
        <Meter label="Token reservations" value={run.usage.reserved_tokens} maximum={run.budgets.token_reservations} />
      </section>
      <section className="panel"><div className="section-head"><h3>Run outcomes</h3><Badge tone={run.finding_count ? 'danger' : 'neutral'}>{run.finding_count} findings</Badge></div>
        <dl className="metrics"><div><dt>Generated candidates</dt><dd>{run.candidate_counts.generated}</dd></div><div><dt>Validated candidates</dt><dd>{run.candidate_counts.validated}</dd></div><div><dt>Tool-reported (untrusted)</dt><dd>{run.tool_reported_count ?? 0}</dd></div><div><dt>Verifier-confirmed</dt><dd>{run.verifier_confirmed_count ?? 0}</dd></div><div><dt>Safety rejections</dt><dd>{run.safety_rejections}</dd></div><div><dt>Linked retest</dt><dd>{run.linked_retests.length ? 'AVAILABLE' : run.retest_of ? 'THIS RUN' : 'NONE'}</dd></div></dl>
      </section>
    </div>
    <section className="panel event-slice"><div className="section-head"><h3>Latest structured events</h3><button className="text-button" onClick={() => onOpenRun(run.id)}>Full chronological replay →</button></div>{runEvents.slice(-5).reverse().map((event) => <EventRow key={event.event_id} event={event} />)}</section>
  </div>
}

function EventRow({ event, onClick }: { event: EventRecord; onClick?: () => void }) {
  return <button className="event-row" onClick={onClick} disabled={!onClick}>
    <time>{new Date(event.timestamp).toLocaleTimeString()}</time><Badge tone={event.actor_type.toLowerCase()}>{event.actor_type}</Badge><span className="event-stage">{event.stage.replaceAll('_', ' ')}</span><span className="event-summary">{event.summary}</span><Badge tone={event.status === 'FAILED' || event.status === 'REJECTED' ? 'warning' : 'neutral'}>{event.status}</Badge><span className="mono event-id">{short(event.scan_id, 12)}</span>
  </button>
}

function RunList({ runs, onOpen }: { runs: Run[]; onOpen: (id: string) => void }) {
  if (!runs.length) return <Empty title="No historical runs" copy="Completed and active scans will appear here in stable creation order." />
  return <section className="panel table-panel"><div className="section-head"><div><p className="eyebrow">HISTORICAL INDEX</p><h2>Runs</h2></div><span className="muted">{runs.length} local records</span></div><div className="table-scroll"><table><thead><tr><th>Run</th><th>Status</th><th>Profile</th><th>Engine</th><th>Model</th><th>Requests</th><th>Candidates</th><th>Findings</th><th>Retest</th><th>Started</th></tr></thead><tbody>{runs.map((run) => <tr key={run.id} onClick={() => onOpen(run.id)} tabIndex={0}><td className="mono">{short(run.id, 19)}</td><td><Badge tone={run.status === 'FAIL' ? 'danger' : run.status === 'PASS' ? 'good' : 'blue'}>{run.status}</Badge></td><td>{run.variant.toUpperCase()}</td><td className="mono">{run.engine ?? 'AEGIS_NATIVE'}</td><td>{run.model ?? run.planner}</td><td>{run.usage.requests}/{run.budgets.target_requests}</td><td>{run.candidate_counts.validated}/{run.candidate_counts.generated}</td><td>{run.finding_count}</td><td>{run.retest_of ? 'RETEST' : run.linked_retests.length ? 'LINKED' : '—'}</td><td>{when(run.created_at)}</td></tr>)}</tbody></table></div></section>
}

function LifecyclePanel({ lifecycle, policy }: { lifecycle?: LifecycleCard[]; policy?: ExecutionPolicy }) {
  const stages = ['TOOL_REPORTED', 'AEGIS_CORRELATED', 'VERIFIED', 'REVIEW_REQUIRED', 'REJECTED']
  return <div className="two-col">
    <section className="panel"><div className="section-head"><div><p className="eyebrow">FINDING LIFECYCLE</p><h3>Tool-reported vs verifier-confirmed</h3></div><Badge tone="scope">ENGINE ≠ VERIFIER</Badge></div>
      {lifecycle && lifecycle.length ? lifecycle.map((item) => <article className={`lifecycle-card ${item.lifecycle_state.toLowerCase()}`} key={item.normalized_id}>
        <div className="lifecycle-track">{stages.map((stage) => { const reached = stages.indexOf(stage) <= stages.indexOf(item.lifecycle_state) && item.lifecycle_state !== 'REJECTED'; const isState = stage === item.lifecycle_state; return <span key={stage} className={`lifecycle-step ${isState ? 'active' : ''} ${reached ? 'reached' : ''}`}>{stage.replaceAll('_', ' ')}</span> })}</div>
        <dl className="detail-list compact"><div><dt>Engine (untrusted)</dt><dd>{item.engine_reported}</dd></div><div><dt>AI hypothesis</dt><dd>{item.ai_hypothesis}</dd></div><div><dt>Controller authorized</dt><dd className="mono">{item.controller_authorization}</dd></div><div><dt>Provenance</dt><dd><Badge tone={item.provenance === 'VERIFIER' ? 'good' : 'warning'}>{item.provenance}</Badge></dd></div><div><dt>Aegis finding</dt><dd className="mono">{item.aegis_finding_id ?? 'Not promoted'}</dd></div></dl>
      </article>) : <Empty title="No engine-reported findings" copy="This run produced no untrusted engine observation to correlate." />}
    </section>
    <section className="panel"><div className="section-head"><div><p className="eyebrow">EXECUTION POLICY</p><h3>Deterministic decisions</h3></div><Badge tone="scope">{policy ? `KERNEL v${policy.engine_kernel_version ?? '—'}` : 'KERNEL'}</Badge></div>
      <dl className="detail-list"><div><dt>Engine</dt><dd>{policy?.engine ?? '—'}</dd></div><div><dt>Adapter</dt><dd className="mono">{policy?.adapter_version ?? '—'}</dd></div><div><dt>Jobs constructed</dt><dd>{policy?.jobs_created.length ?? 0}</dd></div><div><dt>Jobs rejected (zero traffic)</dt><dd>{policy?.jobs_rejected.length ?? 0}</dd></div></dl>
      {policy?.jobs_created.map((job) => <div className="policy-row" key={job.job_id}><Badge tone="controller">{job.status}</Badge><span className="mono">{short(job.job_id, 16)}</span><small>{job.observation_count} obs · {job.reported_finding_count} reported</small></div>)}
      {policy?.jobs_rejected.map((job, index) => <div className="policy-row rejected" key={index}><Badge tone="warning">{job.code}</Badge><span>{job.engine}</span><small>{job.detail}</small></div>)}
    </section>
  </div>
}

function RunReplay({ detail, onBack }: { detail: { run: Run; events: EventRecord[]; evidence: Evidence[]; lifecycle?: LifecycleCard[]; execution_policy?: ExecutionPolicy }; onBack: () => void }) {
  const [index, setIndex] = useState(Math.max(0, detail.events.length - 1))
  const [following, setFollowing] = useState(false)
  const event = detail.events[index]
  const linkedEvidence = detail.evidence.filter((item) => event?.evidence_refs.some((ref) => ref.evidence_id === item.artifact_id) || event?.event_type === 'OBSERVATION')
  const jump = (types: string[]) => { const found = detail.events.findIndex((item) => types.includes(item.event_type)); if (found >= 0) setIndex(found) }
  return <div className="view-stack replay"><section className="replay-bar panel"><button className="text-button" onClick={onBack}>← Runs</button><div><h2>Chronological replay</h2><p className="mono muted">{detail.run.id}</p></div><div className="replay-controls"><button aria-label="Previous event" onClick={() => setIndex((value) => Math.max(0, value - 1))}>←</button><span>{index + 1} / {detail.events.length}</span><button aria-label="Next event" onClick={() => setIndex((value) => Math.min(detail.events.length - 1, value + 1))}>→</button><button className="secondary" onClick={() => setFollowing(!following)}>{following ? 'Pause live following' : 'Resume live following'}</button></div></section>
    <section className="jump-bar panel"><span>Jump to</span><button onClick={() => jump(['CANDIDATE_GENERATED'])}>Candidate</button><button onClick={() => jump(['REQUEST_STARTED'])}>Request</button><button onClick={() => jump(['VERIFIER_RESULT'])}>Finding</button><button onClick={() => jump(['RETEST_PLAN'])}>Retest</button></section>
    <div className="replay-grid"><section className="panel timeline-panel"><div className="section-head"><h3>Actor-separated timeline</h3><Badge tone={following ? 'good' : 'neutral'}>{following ? 'FOLLOWING' : 'PAUSED'}</Badge></div><div className="vertical-timeline">{detail.events.map((item, itemIndex) => <button key={item.event_id} className={`timeline-node ${item.actor_type.toLowerCase()} ${itemIndex === index ? 'selected' : ''}`} onClick={() => setIndex(itemIndex)}><i /><div><span>{item.stage.replaceAll('_', ' ')}</span><strong>{item.summary}</strong><small>{item.actor_type} · {new Date(item.timestamp).toLocaleTimeString()} · {item.event_id}</small></div></button>)}</div></section>
      <aside className="panel evidence-viewport"><div className="section-head"><h3>Evidence viewport</h3><Badge tone="scope">REDACTED</Badge></div>{event ? <><p className="eyebrow">SELECTED EVENT</p><h4>{event.event_type.replaceAll('_', ' ')}</h4><p>{event.summary}</p><dl className="detail-list"><div><dt>Actor</dt><dd>{event.actor_type}</dd></div><div><dt>Engine</dt><dd>{event.engine}</dd></div><div><dt>Status</dt><dd>{event.status}</dd></div><div><dt>Integrity</dt><dd className="mono">SHA-256 · {short(event.integrity.digest, 20)}</dd></div></dl>{(linkedEvidence.length ? linkedEvidence : detail.evidence.slice(0, 3)).map((card) => <EvidenceCard key={card.artifact_id} card={card} />)}</> : <Empty title="No event selected" copy="Choose an event from the replay." />}</aside></div>
    <LifecyclePanel lifecycle={detail.lifecycle} policy={detail.execution_policy} />
    <section className="panel comparison"><div><p className="eyebrow">DISCOVERY</p><h3>Vulnerable</h3><strong>200 / 200 / 200</strong><small>Owner control · alternate-owner control · cross-owner probe</small></div><span>→</span><div><p className="eyebrow">LINKED RETEST</p><h3>Patched</h3><strong className="good-text">200 / 200 / 403</strong><small>Same controller-constructed access direction · remediation PASS</small></div></section>
  </div>
}

function EvidenceCard({ card }: { card: Evidence }) {
  return <article className="evidence-card"><div className="evidence-title"><Badge tone="blue">API_EVIDENCE_CARD</Badge><span>{card.control_probe_role}</span></div><div className="request-line"><b>{card.method}</b><code>{card.normalized_route}</code><strong className={card.response_status === 403 ? 'good-text' : ''}>{card.response_status ?? 'ERR'}</strong></div><dl className="detail-list compact"><div><dt>Principal</dt><dd>{card.principal_profile_name}</dd></div><div><dt>Object</dt><dd>{card.object_reference}</dd></div><div><dt>Request</dt><dd className="mono">{short(card.request_id, 20)}</dd></div><div><dt>Evidence hash</dt><dd className="mono">{short(card.evidence_hash, 18)}</dd></div></dl><p className="redaction-note">Response body, credentials, cookies, and sensitive values omitted.</p></article>
}

function FindingsView({ findings, selected, setSelected }: { findings: Finding[]; selected?: Finding; setSelected: (finding?: Finding) => void }) {
  if (selected) return <FindingDetail finding={selected} onBack={() => setSelected(undefined)} />
  if (!findings.length) return <Empty title="No verifier-confirmed findings" copy="Hypotheses and incomplete evidence never appear as confirmed findings." />
  return <section className="panel table-panel"><div className="section-head"><div><p className="eyebrow">VERIFIER-OWNED RECORDS</p><h2>Findings</h2></div><Badge tone="scope">AEGIS NATIVE</Badge></div><div className="table-scroll"><table><thead><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>Status</th><th>OWASP</th><th>Operation</th><th>Direction</th><th>Evidence</th><th>Retest</th></tr></thead><tbody>{findings.map((finding) => <tr key={finding.id} onClick={() => setSelected(finding)} tabIndex={0}><td><Badge tone="danger">{finding.severity}</Badge></td><td><strong>{finding.title}</strong><small className="mono block">{short(finding.id, 22)}</small></td><td>{finding.confidence}</td><td><Badge tone={finding.status === 'REMEDIATED' ? 'good' : 'danger'}>{finding.status}</Badge></td><td>{finding.owasp_mapping}</td><td className="mono">{finding.affected_operation}</td><td>{finding.principal_object_direction}</td><td>{finding.evidence_completeness}</td><td className="mono">{short(finding.linked_retest, 14)}</td></tr>)}</tbody></table></div></section>
}

function FindingDetail({ finding, onBack }: { finding: Finding; onBack: () => void }) {
  const steps = [['AI hypothesis', finding.ai_hypothesis, 'ai'], ['Controller execution', finding.controller_execution, 'controller'], ['Deterministic evidence', finding.deterministic_evidence, 'controller'], ['Verifier conclusion', finding.verifier_conclusion, 'verifier'], ['Patched retest', finding.patched_retest, 'controller'], ['Final state', finding.final_state, 'verifier']]
  return <div className="view-stack"><section className="panel finding-head"><button className="text-button" onClick={onBack}>← Findings</button><div><div className="badge-line"><Badge tone="danger">{finding.severity}</Badge><Badge tone="good">{finding.confidence}</Badge><Badge tone="scope">{finding.source_engine}</Badge></div><h2>{finding.title}</h2><p className="mono muted">{finding.id}</p></div><Badge tone={finding.status === 'REMEDIATED' ? 'good' : 'danger'}>{finding.status}</Badge></section><div className="two-col"><section className="panel"><h3>Technical record</h3><dl className="detail-list"><div><dt>Class</dt><dd>{finding.vulnerability_class}</dd></div><div><dt>OWASP</dt><dd>{finding.owasp_mapping}</dd></div><div><dt>Operation</dt><dd className="mono">{finding.affected_operation}</dd></div><div><dt>Direction</dt><dd>{finding.principal_object_direction}</dd></div><div><dt>Discovery scan</dt><dd className="mono">{finding.discovery_scan}</dd></div><div><dt>Linked retest</dt><dd className="mono">{finding.linked_retest ?? 'Not available'}</dd></div></dl></section><section className="panel comparison compact-comparison"><div><span>VULNERABLE</span><strong>200 / 200 / 200</strong></div><span>→</span><div><span>PATCHED</span><strong className="good-text">200 / 200 / 403</strong></div></section></div><section className="panel"><div className="section-head"><h3>Responsibility chain</h3><span className="muted">Finding provenance: {finding.provenance}</span></div><div className="provenance-chain">{steps.map(([title, copy, tone], index) => <div className={`provenance-step ${tone}`} key={title}><i>{index + 1}</i><div><strong>{title}</strong><p>{copy}</p></div></div>)}</div></section></div>
}

function AuditView({ events }: { events: EventRecord[] }) {
  const [filters, setFilters] = useState({ q: '', actor: '', stage: '', status: '', engine: '', event: '' })
  const [selected, setSelected] = useState<EventRecord>()
  const filtered = events.filter((event) => {
    const haystack = `${event.summary} ${event.scan_id} ${event.finding_id ?? ''} ${event.event_type}`.toLowerCase()
    return (!filters.q || haystack.includes(filters.q.toLowerCase())) && (!filters.actor || event.actor_type === filters.actor) && (!filters.stage || event.stage === filters.stage) && (!filters.status || event.status === filters.status) && (!filters.engine || event.engine === filters.engine) && (!filters.event || event.event_type === filters.event)
  })
  const update = (key: keyof typeof filters, value: string) => setFilters((current) => ({ ...current, [key]: value }))
  return <div className="view-stack"><section className="panel filter-panel"><div className="section-head"><div><p className="eyebrow">SEARCHABLE STRUCTURED RECORD</p><h2>Audit Explorer</h2></div><Badge tone="scope">CHECKSUMMED · REDACTED</Badge></div><div className="filters"><label className="search-field"><span>Search IDs or summaries</span><input value={filters.q} onChange={(e) => update('q', e.target.value)} placeholder="scan, finding, event…" /></label>{(['actor', 'stage', 'status', 'engine', 'event'] as const).map((key) => <label key={key}><span>{key === 'event' ? 'Event type' : key}</span><select value={filters[key]} onChange={(e) => update(key, e.target.value)}><option value="">All</option>{Array.from(new Set(events.map((item) => key === 'actor' ? item.actor_type : key === 'event' ? item.event_type : item[key]))).sort().map((value) => <option key={value}>{value}</option>)}</select></label>)}</div></section><section className="panel audit-list"><div className="audit-header"><span>Time</span><span>Actor</span><span>Stage</span><span>Summary</span><span>Status</span><span>Entity</span></div>{filtered.length ? filtered.slice().reverse().map((event) => <EventRow key={event.event_id} event={event} onClick={() => setSelected(event)} />) : <Empty title="No matching events" copy="Adjust the filters to expand the structured audit record." />}</section>{selected && <EventDrawer event={selected} onClose={() => setSelected(undefined)} />}</div>
}

function EventDrawer({ event, onClose }: { event: EventRecord; onClose: () => void }) {
  return <div className="drawer-scrim" onClick={onClose}><aside className="drawer" onClick={(e) => e.stopPropagation()} aria-label="Audit event detail"><div className="drawer-head"><div><p className="eyebrow">STRUCTURED EVENT</p><h2>{event.event_type.replaceAll('_', ' ')}</h2></div><button aria-label="Close detail" onClick={onClose}>×</button></div><div className="badge-line"><Badge tone={event.actor_type.toLowerCase()}>{event.actor_type}</Badge><Badge>{event.stage}</Badge><Badge>{event.status}</Badge></div><p className="drawer-summary">{event.summary}</p><dl className="detail-list"><div><dt>Event ID</dt><dd className="mono">{event.event_id}</dd></div><div><dt>Sequence</dt><dd>{event.sequence}</dd></div><div><dt>Timestamp</dt><dd>{when(event.timestamp)}</dd></div><div><dt>Scan</dt><dd className="mono">{event.scan_id}</dd></div><div><dt>Finding</dt><dd className="mono">{event.finding_id ?? '—'}</dd></div><div><dt>Retest</dt><dd className="mono">{event.retest_scan_id ?? '—'}</dd></div><div><dt>Parent event</dt><dd className="mono">{event.parent_event_id ?? '—'}</dd></div><div><dt>Child events</dt><dd className="mono">{event.child_event_ids?.join(', ') || '—'}</dd></div><div><dt>Engine</dt><dd>{event.engine}</dd></div><div><dt>Redaction</dt><dd>{event.redaction_status}</dd></div></dl><h3>Redacted metadata</h3><pre>{JSON.stringify(event.metadata, null, 2)}</pre><h3>Evidence references</h3><pre>{JSON.stringify(event.evidence_refs, null, 2)}</pre><h3>Integrity</h3><p className="mono digest">{event.integrity.algorithm} · {event.integrity.digest}</p></aside></div>
}

function EvidenceView({ evidence, screenshotPolicy }: { evidence: Evidence[]; screenshotPolicy: Record<string, unknown> | null }) {
  return <div className="view-stack"><section className="panel"><div className="section-head"><div><p className="eyebrow">APPROVED REDACTED FIELDS ONLY</p><h2>Evidence</h2></div><Badge tone="scope">NO RAW RESPONSES</Badge></div>{evidence.length ? <div className="evidence-grid">{evidence.map((card) => <EvidenceCard key={card.artifact_id} card={card} />)}</div> : <Empty title="No API evidence cards loaded" copy="Select or execute a run with fresh deterministic evidence." />}</section><section className="panel screenshot-fixture"><div><Badge tone="warning">BROWSER_SCREENSHOT · FIXTURE · NOT SCAN EVIDENCE</Badge><h3>Browser capture interface inactive</h3><p>No approved browser runner is connected. Screenshots are disabled by default, restricted to synthetic allowlisted origins, redacted before persistence, quota-bound, and never sent to the LLM by default.</p></div><dl className="detail-list"><div><dt>Capture runner</dt><dd>INACTIVE</dd></div><div><dt>Storage</dt><dd>LOCAL / PROJECT-SCOPED</dd></div><div><dt>Enabled</dt><dd>NO</dd></div><div><dt>Policy loaded</dt><dd>{screenshotPolicy ? 'YES' : 'UNAVAILABLE'}</dd></div></dl></section></div>
}

function ReadyDot({ label, value }: { label: string; value: boolean | null }) {
  const state = value === null ? 'unknown' : value ? 'ok' : 'bad'
  const text = value === null ? 'N/A' : value ? 'YES' : 'NO'
  return <div className={`ready-state ${state}`}><i /><span>{label}</span><strong>{text}</strong></div>
}

function IntegrationsView({ integrations, engines }: { integrations: Integration[]; engines: EngineReadiness[] }) {
  return <div className="view-stack">
    <section className="panel"><div className="section-head"><div><p className="eyebrow">ENGINE REGISTRY</p><h2>Integrations</h2></div><span className="muted">Aegis Native and the bounded Nuclei profile are operational in Phase 1.2</span></div><div className="integration-grid">{integrations.map((item) => <article className={`integration-card ${item.state.toLowerCase()}`} key={item.name}><div className="integration-mark">{item.name.slice(0, 1)}</div><div><h3>{item.name}</h3><p>{item.engine}</p>{item.model && <p className="mono">{item.model} · {short(item.digest, 14)}</p>}</div><Badge tone={item.state === 'CONNECTED' ? 'good' : item.state.startsWith('PLANNED') ? 'neutral' : 'warning'}>{item.state.replaceAll('_', ' ')}</Badge></article>)}</div></section>
    <section className="panel"><div className="section-head"><div><p className="eyebrow">INTEGRATION READINESS · SECURITY-TOOL KERNEL</p><h2>Engine adapters</h2></div><Badge tone="scope">CONFIGURED ≠ ENABLED ≠ REACHABLE ≠ AUTHORIZED</Badge></div><div className="engine-grid">{engines.map((engine) => {
      const provenance = engine.engine === 'NUCLEI' ? engine.provenance : null
      const latest = provenance?.latest_execution
      return <article className={`engine-card ${engine.enabled ? 'enabled' : 'disabled'}`} key={engine.engine}><div className="engine-head"><div><h3>{engine.name}</h3><p className="mono">{engine.engine} · {engine.adapter_version ?? '—'}</p></div><Badge tone={engine.enabled ? 'good' : 'neutral'}>{engine.state}</Badge></div><div className="ready-grid"><ReadyDot label="Configured" value={engine.configured} /><ReadyDot label="Reachable" value={engine.reachable} /><ReadyDot label="Enabled" value={engine.enabled} /><ReadyDot label="Authorized" value={engine.authorized} /></div><p className="engine-detail">{engine.detail}</p>{provenance && <div className="nuclei-provenance"><dl className="detail-list compact"><div><dt>Engine pin</dt><dd className="mono">{provenance.pinned_engine_version ?? '—'} · {short(provenance.attested_binary_sha256, 20)}</dd></div><div><dt>Template manifest</dt><dd className="mono">{provenance.manifest_version ?? '—'} · {short(provenance.manifest_digest, 20)}</dd></div><div><dt>Admitted templates</dt><dd>{provenance.admitted_template_count ?? 0} · signature {provenance.signature_probe ?? '—'}</dd></div><div><dt>Last health check</dt><dd>{when(provenance.last_health_check)}</dd></div><div><dt>Latest execution</dt><dd>{latest ? <><span className="mono">{short(latest.scan_id, 18)}</span> · {latest.status} · {latest.http_connections ?? 0}/{latest.request_budget ?? 0} requests · {latest.records ?? 0} results</> : 'No execution recorded'}</dd></div><div><dt>Finding authority</dt><dd>{latest ? `${latest.tool_reported ?? 0} tool-reported · ${latest.verifier_confirmed ?? 0} verifier-confirmed` : 'No finding lifecycle recorded'}</dd></div></dl><p className="responsibility-note">{provenance.responsibility}</p></div>}{!engine.enabled && <p className="isolation-note"><b>Future isolation boundary:</b> {engine.isolation_boundary}</p>}</article>
    })}</div></section>
  </div>
}

function HealthView({ health }: { health: Record<string, unknown> | null }) {
  if (!health) return <Empty title="Health checks unavailable" copy="The console could not load current subsystem checks." />
  const checks = [['Control plane', health.control_plane], ['Gateway', health.gateway], ['Ollama', health.ollama], ['Synthetic lab', health.lab], ['Dashboard / API', health.dashboard_api], ['Database', health.database], ['Network isolation', health.network_isolation], ['Topology test', health.last_topology_test], ['Secret scan', health.last_secret_scan]]
  return <div className="view-stack"><section className="panel"><div className="section-head"><div><p className="eyebrow">ACTUAL RUNTIME CHECKS</p><h2>System Health</h2></div><span className="muted">Checked {when(String(health.checked_at))}</span></div><div className="health-grid">{checks.map(([label, value]) => { const text = String(value ?? 'UNKNOWN'); const okay = text === 'HEALTHY'; return <div className="health-card" key={String(label)}><i className={okay ? 'ok' : text.includes('UNAVAILABLE') ? 'bad' : 'unknown'} /><span>{String(label)}</span><strong>{text.replaceAll('_', ' ')}</strong></div> })}</div></section><div className="two-col"><section className="panel"><h3>Model runtime</h3><dl className="detail-list"><div><dt>Model</dt><dd>{String(health.model ?? '—')}</dd></div><div><dt>Digest</dt><dd className="mono">{short(String(health.model_digest ?? ''), 28)}</dd></div></dl></section><section className="panel"><h3>Event & evidence state</h3><pre>{JSON.stringify({ event_stream: health.event_stream, evidence_storage: health.evidence_storage }, null, 2)}</pre></section></div></div>
}

function ManagementView({ finding, onClose }: { finding?: Finding; onClose: () => void }) {
  return <div className="management"><header><div className="brand"><i>A</i><span>AEGIS</span></div><Badge tone="scope">MANAGEMENT VIEW · PHASE 1.2</Badge><button onClick={onClose}>Exit presentation</button></header><main><ScopeBadges /><p className="eyebrow">LOCAL, BOUNDED, DETERMINISTIC</p><h1>The AI proposes.<br /><span>The system proves.</span></h1><p className="management-narrative">The local AI model analyzes a projected API surface and independently proposes an object-authorization attack hypothesis. A deterministic policy layer validates scope and safety, compiles approved read-only requests, and executes the test. A deterministic verifier confirms the result from fresh evidence. After remediation, the controller repeats the same access direction and verifies that the unauthorized request is denied.</p><p className="management-narrative">Nuclei is an Aegis-controlled detection engine. Its results are independently correlated and verified; Nuclei does not directly confirm Aegis findings.</p><div className="management-flow"><article className="ai"><span>01</span><h2>Private AI hypothesis</h2><p>Projected API metadata only. Zero external model egress.</p></article><article className="controller"><span>02</span><h2>Deterministic controls</h2><p>Scope, safety, compilation and bounded execution.</p></article><article className="verifier"><span>03</span><h2>Verified evidence</h2><p>Fresh deterministic evidence confirms the technical result.</p></article><article className="verifier"><span>04</span><h2>Remediation verified</h2><p>Linked retests require independently verified patched evidence before PASS.</p></article></div>{finding && <div className="management-result"><div><span>CONFIRMED</span><strong>{finding.severity} · {finding.vulnerability_class}</strong></div><div><span>{finding.linked_retest ? 'RETEST' : 'FINDING STATE'}</span><strong className="good-text">{finding.final_state}</strong></div></div>}<section className="limitations"><h2>Honest limitations</h2><ul><li>Synthetic lab</li><li>One read-only BOLA capability</li><li>One signed Nuclei template</li><li>No broad vulnerability coverage</li><li>Not production readiness</li><li>Not unrestricted autonomous pentesting</li></ul></section></main></div>
}

export function App() {
  const [view, setView] = useState<View>('Mission Control')
  const [runs, setRuns] = useState<Run[]>([])
  const [events, setEvents] = useState<EventRecord[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [integrations, setIntegrations] = useState<Integration[]>([])
  const [engines, setEngines] = useState<EngineReadiness[]>([])
  const [health, setHealth] = useState<Record<string, unknown> | null>(null)
  const [screenshotPolicy, setScreenshotPolicy] = useState<Record<string, unknown> | null>(null)
  const [selectedRun, setSelectedRun] = useState<{ run: Run; events: EventRecord[]; evidence: Evidence[]; lifecycle?: LifecycleCard[]; execution_policy?: ExecutionPolicy }>()
  const [selectedFinding, setSelectedFinding] = useState<Finding>()
  const [streamState, setStreamState] = useState<StreamState>('CONNECTING')
  const [error, setError] = useState<string>()
  const [loading, setLoading] = useState(true)
  const [presentation, setPresentation] = useState(new URLSearchParams(location.search).get('presentation') === '1')
  const lastSequence = useRef(0)

  const hydrate = useCallback(async () => {
    try {
      const [runData, auditItems, findingData, integrationData, engineData, healthData, screenshotData] = await Promise.all([
        api<{ items: Run[] }>('/api/console/runs'), auditHistory(), api<{ items: Finding[] }>('/api/console/findings'), api<{ items: Integration[] }>('/api/console/integrations'), api<{ items: EngineReadiness[] }>('/api/console/engines'), api<Record<string, unknown>>('/api/console/health'), api<Record<string, unknown>>('/api/console/screenshots'),
      ])
      setRuns(runData.items); setEvents(auditItems); setFindings(findingData.items); setIntegrations(integrationData.items); setEngines(engineData.items ?? []); setHealth(healthData); setScreenshotPolicy(screenshotData)
      lastSequence.current = auditItems.at(-1)?.sequence ?? 0
      setError(undefined)
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Console data is unavailable') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { void hydrate() }, [hydrate])
  useEffect(() => {
    const source = new EventSource(`/api/console/events?cursor=${lastSequence.current}`)
    source.onopen = () => setStreamState('LIVE')
    source.addEventListener('gap', () => { setStreamState('GAP'); void hydrate() })
    source.addEventListener('audit', (message) => {
      const incoming = JSON.parse((message as MessageEvent<string>).data) as EventRecord
      if (incoming.sequence > lastSequence.current + 1 && lastSequence.current > 0) setStreamState('GAP')
      if (incoming.sequence <= lastSequence.current) return
      lastSequence.current = incoming.sequence
      setEvents((current) => [...current, incoming].slice(-500))
      setStreamState('LIVE')
    })
    source.onerror = () => setStreamState('STALE')
    return () => source.close()
  }, [hydrate])

  const activeRun = useMemo(() => runs.find((run) => ['RUNNING', 'QUEUED'].includes(run.status)) ?? runs[0], [runs])
  const evidence = selectedRun?.evidence ?? []
  const openRun = async (id: string) => { try { const detail = await api<{ run: Run; events: EventRecord[]; evidence: Evidence[]; lifecycle?: LifecycleCard[]; execution_policy?: ExecutionPolicy }>(`/api/console/runs/${encodeURIComponent(id)}`); setSelectedRun(detail); setView('Runs') } catch { setError('Run detail could not be loaded.') } }
  const chooseView = (next: View) => { setView(next); if (next !== 'Runs') setSelectedRun(undefined); if (next !== 'Findings') setSelectedFinding(undefined) }

  if (presentation) return <ManagementView finding={findings[0]} onClose={() => setPresentation(false)} />
  return <div className="shell"><aside className="sidebar"><a className="brand" href="/console/"><i>A</i><span>AEGIS<small>Operator Console</small></span></a><nav>{NAV.map((item, index) => <button className={view === item ? 'active' : ''} onClick={() => chooseView(item)} key={item}><span>{String(index + 1).padStart(2, '0')}</span>{item}</button>)}</nav><div className="sidebar-foot"><a href="/">Engineering dashboard ↗</a><button onClick={() => setPresentation(true)}>Presentation mode</button><div className={`stream-state ${streamState.toLowerCase()}`}><i />Event stream · {streamState}</div><small>Structured, checksummed audit evidence<br />Not an immutable audit store</small></div></aside><div className="workspace"><header className="topbar"><div><p className="eyebrow">AEGIS NATIVE · LOCAL CONTROL PLANE</p><h1>{selectedRun ? 'Run Replay' : view}</h1></div><ScopeBadges /></header>{error && <div className="error-banner" role="alert"><strong>Console degraded</strong><span>{error}. Persisted views may be stale.</span><button onClick={() => void hydrate()}>Retry</button></div>}<main>{loading ? <Loading /> : selectedRun && view === 'Runs' ? <RunReplay detail={selectedRun} onBack={() => setSelectedRun(undefined)} /> : view === 'Mission Control' ? <MissionControl run={activeRun} events={events} onOpenRun={(id) => void openRun(id)} streamState={streamState} /> : view === 'Runs' ? <RunList runs={runs} onOpen={(id) => void openRun(id)} /> : view === 'Findings' ? <FindingsView findings={findings} selected={selectedFinding} setSelected={setSelectedFinding} /> : view === 'Audit' ? <AuditView events={events} /> : view === 'Evidence' ? <EvidenceView evidence={evidence} screenshotPolicy={screenshotPolicy} /> : view === 'Integrations' ? <IntegrationsView integrations={integrations} engines={engines} /> : <HealthView health={health} />}</main></div></div>
}
