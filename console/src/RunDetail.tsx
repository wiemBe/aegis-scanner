import { useState } from 'react'
import type { EventRecord, Evidence, Finding, RunDetail as RunDetailData } from './api'
import { Empty, Kv, Pill, RunStatePill } from './components'
import { elapsed, findingStateView, runStateView, short, time, when } from './format'

type Tab = 'Overview' | 'Activity' | 'Findings' | 'Evidence' | 'Cleanup' | 'Report'
const TABS: Tab[] = ['Overview', 'Activity', 'Findings', 'Evidence', 'Cleanup', 'Report']

const actorTone = (actor: EventRecord['actor_type']) =>
  actor === 'VERIFIER' ? 'success' : actor === 'CONTROLLER' ? 'neutral' : actor === 'AI_PLANNER' ? 'warning' : 'neutral'

export function RunDetailView({
  detail,
  findings,
  onBack,
  initialTab = 'Overview',
}: {
  detail: RunDetailData
  findings: Finding[]
  onBack: () => void
  initialTab?: Tab
}) {
  const { run, events, evidence } = detail
  const [tab, setTab] = useState<Tab>(initialTab)
  const [confirmStop, setConfirmStop] = useState(false)
  const terminal =
    run.status === 'PASS' ||
    run.status === 'FAIL' ||
    run.status === 'REVIEW' ||
    run.status === 'INCOMPLETE'
  const runFindings = findings.filter(
    (f) => f.discovery_scan === run.id || f.linked_retest === run.id,
  )

  // Honest stop capability: the native in-process assessment runs as one atomic controller
  // transaction with no cancellable mid-flight state, so mid-flight cancellation is NOT_EVALUATED.
  const stopReason = terminal
    ? 'This assessment has already completed. There is nothing left to stop.'
    : 'This assessment runs as one atomic controller transaction with no cancellable mid-flight state. Mid-flight cancellation is not evaluated for this profile.'

  return (
    <div className="stack">
      <button className="btn ghost" style={{ alignSelf: 'flex-start' }} onClick={onBack}>
        ← Runs
      </button>

      <div className="panel">
        <div className="panel-head">
          <div>
            <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              {run.target_name}
              <RunStatePill status={run.status} />
            </h2>
            <div className="mono muted" style={{ marginTop: 4 }}>
              {run.id}
            </div>
          </div>
          <div style={{ position: 'relative' }}>
            <button className="btn danger" disabled onClick={() => setConfirmStop(true)}>
              Stop assessment
            </button>
          </div>
        </div>
        <div className="run-summary">
          <div className="cell">
            <span>Assessment</span>
            <strong>{run.engine ?? 'AEGIS_NATIVE'}</strong>
          </div>
          <div className="cell">
            <span>State</span>
            <strong>{runStateView(run.status).label}</strong>
          </div>
          <div className="cell">
            <span>Elapsed</span>
            <strong>{elapsed(run)}</strong>
          </div>
          <div className="cell">
            <span>Requests</span>
            <strong>
              {run.usage.requests} / {run.budgets.target_requests}
            </strong>
          </div>
          <div className="cell">
            <span>Findings</span>
            <strong>{run.finding_count}</strong>
          </div>
          <div className="cell">
            <span>Cleanup</span>
            <strong>Complete</strong>
          </div>
        </div>
        <p className="redaction-note" style={{ marginTop: 12 }}>
          Stop is unavailable: {stopReason}
        </p>
      </div>

      <div>
        <div className="tabs" role="tablist">
          {TABS.map((name) => (
            <button
              key={name}
              role="tab"
              aria-selected={tab === name}
              className={`tab ${tab === name ? 'active' : ''}`}
              onClick={() => setTab(name)}
            >
              {name}
            </button>
          ))}
        </div>

        {tab === 'Overview' && <Overview detail={detail} findingCount={runFindings.length} />}
        {tab === 'Activity' && <Activity events={events} />}
        {tab === 'Findings' && <FindingsPanel findings={runFindings} />}
        {tab === 'Evidence' && <EvidencePanel evidence={evidence} />}
        {tab === 'Cleanup' && <Cleanup />}
        {tab === 'Report' && <Report detail={detail} findings={runFindings} />}
      </div>

      {confirmStop && (
        <div className="modal-scrim" onClick={() => setConfirmStop(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>Stop assessment</h2>
            <p>{stopReason}</p>
            <div className="modal-actions">
              <button className="btn" onClick={() => setConfirmStop(false)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Overview({ detail, findingCount }: { detail: RunDetailData; findingCount: number }) {
  const { run } = detail
  const phase =
    run.status === 'RUNNING' || run.status === 'QUEUED'
      ? 'In progress'
      : run.verification === 'CONFIRMED'
        ? 'Verification complete — findings confirmed'
        : run.status === 'PASS'
          ? 'Verification complete — remediation passed'
          : 'Verification complete'
  return (
    <div className="grid-2">
      <div className="panel">
        <div className="panel-head">
          <h3>Summary</h3>
        </div>
        <p style={{ marginTop: 0 }}>
          {phase}. The assessment executed {run.usage.requests} controller-compiled request(s) and
          produced {findingCount} verifier-owned finding(s).
        </p>
        <Kv
          items={[
            ['Profile', run.variant.toUpperCase()],
            ['Planner', run.planner],
            ['Started', when(run.created_at)],
            ['Completed', when(run.completed_at)],
            ['Terminal reason', run.terminal_reason ?? '—'],
          ]}
        />
      </div>
      <div className="panel">
        <div className="panel-head">
          <h3>Outcomes</h3>
        </div>
        <Kv
          items={[
            ['Candidates generated', run.candidate_counts.generated],
            ['Candidates validated', run.candidate_counts.validated],
            ['Tool-reported (untrusted)', run.tool_reported_count ?? 0],
            ['Verifier-confirmed', run.verifier_confirmed_count ?? run.finding_count],
            ['Safety rejections', run.safety_rejections],
            [
              'Linked retest',
              run.linked_retests.length ? 'Available' : run.retest_of ? 'This run' : 'None',
            ],
          ]}
        />
      </div>
    </div>
  )
}

function Activity({ events }: { events: EventRecord[] }) {
  if (!events.length) return <Empty title="No activity yet" copy="Structured events appear here as the assessment runs." />
  return (
    <div className="panel">
      <div className="panel-head">
        <h3>Activity</h3>
        <span className="sub">Structured, checksummed audit events</span>
      </div>
      {events.map((event) => (
        <div className="activity-item" key={event.event_id}>
          <time>{time(event.timestamp)}</time>
          <Pill tone={actorTone(event.actor_type)}>{event.actor_type.replace('_', ' ')}</Pill>
          <span className="summary">
            {event.stage.replaceAll('_', ' ')} — {event.summary}
          </span>
          <span className="addr mono">{short(event.scan_id, 14)}</span>
        </div>
      ))}
    </div>
  )
}

function FindingsPanel({ findings }: { findings: Finding[] }) {
  if (!findings.length)
    return (
      <Empty
        title="No confirmed findings"
        copy="Hypotheses and incomplete evidence are never shown here as findings. Only the independent verifier can confirm a finding."
      />
    )
  return (
    <div>
      {findings.map((finding) => {
        const state = findingStateView(finding)
        return (
          <div
            className={`finding-card ${finding.status === 'REMEDIATED' ? 'remediated' : 'confirmed'}`}
            key={finding.id}
          >
            <div className="fc-head">
              <span className="fc-title">{finding.title}</span>
              <Pill tone={state.tone}>{state.label}</Pill>
              <Pill tone={state.tone === 'success' ? 'success' : 'critical'}>{finding.severity}</Pill>
            </div>
            <Kv
              items={[
                ['Class', finding.vulnerability_class],
                ['OWASP', finding.owasp_mapping],
                ['Operation', <span className="mono">{finding.affected_operation}</span>],
                ['Direction', finding.principal_object_direction],
                ['Evidence', finding.deterministic_evidence],
                ['Verifier', finding.verifier_conclusion],
                ['Retest', finding.patched_retest],
              ]}
            />
            <span className="mono muted" style={{ fontSize: 11 }}>
              {finding.id}
            </span>
          </div>
        )
      })}
    </div>
  )
}

function EvidencePanel({ evidence }: { evidence: Evidence[] }) {
  if (!evidence.length)
    return <Empty title="No evidence cards" copy="This run produced no persisted evidence records." />
  return (
    <div>
      <div className="banner info">
        <div className="banner-body">Approved redacted fields only. Response bodies, credentials and cookies are never shown.</div>
      </div>
      {evidence.map((card) => {
        const untrusted = card.provenance === 'TOOL_REPORTED'
        return (
          <div className="evidence-card" key={card.artifact_id}>
            <div className="fc-head">
              <Pill tone={untrusted ? 'warning' : card.provenance === 'VERIFIER' ? 'success' : 'neutral'}>
                {card.artifact_type}
              </Pill>
              <span className="muted">{card.control_probe_role}</span>
            </div>
            <div className="req-line">
              <b>{card.method}</b>
              <code>{card.normalized_route}</code>
              <strong style={{ color: card.response_status === 403 ? 'var(--success)' : 'inherit' }}>
                {card.response_status ?? '—'}
              </strong>
            </div>
            <Kv
              items={[
                ['Principal', card.principal_profile_name],
                ['Object', card.object_reference],
                ['Request', <span className="mono">{short(card.request_id, 20)}</span>],
                ['Evidence hash', <span className="mono">{short(card.evidence_hash, 20)}</span>],
                ['Captured', when(card.timestamp)],
              ]}
            />
            <p className="redaction-note">
              Response body, credentials, cookies and sensitive values omitted.
              {untrusted ? ' Tool output is untrusted until the independent verifier concludes.' : ''}
            </p>
          </div>
        )
      })}
    </div>
  )
}

function Cleanup() {
  return (
    <div className="panel">
      <div className="panel-head">
        <h3>Cleanup</h3>
        <Pill tone="success">Complete</Pill>
      </div>
      <p style={{ marginTop: 0 }}>
        This assessment ran in-process. No disposable containers or networks were created, so none
        remain.
      </p>
      <Kv
        items={[
          ['State', 'COMPLETED'],
          ['down_rc', 'Not applicable (no container stack)'],
          ['Remaining containers / networks', 'None'],
          ['Credential isolation', 'Synthetic credentials resolved only inside the executor boundary'],
        ]}
      />
    </div>
  )
}

function Report({ detail, findings }: { detail: RunDetailData; findings: Finding[] }) {
  const { run } = detail
  return (
    <div className="stack">
      <div className="panel">
        <div className="panel-head">
          <h3>Evidence report</h3>
          <Pill tone="neutral">OFFLINE · DETERMINISTIC</Pill>
        </div>
        <p style={{ marginTop: 0 }} className="muted">
          Assembled from the controller's persisted, verifier-owned records for this run.
        </p>
        <Kv
          items={[
            ['Run', <span className="mono">{run.id}</span>],
            ['Target', run.target_name],
            ['Outcome', runStateView(run.status).label],
            ['Confirmed findings', findings.filter((f) => f.confidence === 'CONFIRMED' && f.status !== 'REMEDIATED').length],
            ['Remediated', findings.filter((f) => f.status === 'REMEDIATED').length],
            ['Provenance', 'VERIFIER'],
          ]}
        />
        {findings.map((f) => (
          <div key={f.id} style={{ borderTop: '1px solid var(--border)', paddingTop: 10, marginTop: 10 }}>
            <strong>{f.title}</strong>
            <p className="muted" style={{ margin: '4px 0 0', fontSize: 12.5 }}>
              {f.owasp_mapping} · {f.deterministic_evidence} · {f.final_state}
            </p>
          </div>
        ))}
      </div>
      <div className="panel">
        <div className="panel-head">
          <h3>Live Report Agent</h3>
          <Pill tone="neutral">NOT EVALUATED</Pill>
        </div>
        <p style={{ margin: 0 }} className="muted">
          The live model-backed Report Agent was not run for this assessment. It requires the paid
          provider pipeline, which is out of scope for this deployment.
        </p>
      </div>
    </div>
  )
}
