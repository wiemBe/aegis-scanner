import { useCallback, useEffect, useMemo, useState } from 'react'
import type {
  AssessmentProfile,
  ConsoleConfig,
  Finding,
  Health,
  Run,
  RunDetail,
  TargetEntry,
} from './api'
import { consoleApi } from './api'
import { Empty, HealthDot, Kv, Loading, Pill, RunStatePill } from './components'
import { findingStateView, short, when } from './format'
import { NewAssessment } from './NewAssessment'
import { RunDetailView } from './RunDetail'

type Route =
  | { name: 'home' }
  | { name: 'new' }
  | { name: 'runs' }
  | { name: 'run'; id: string; tab?: 'Report' }
  | { name: 'findings' }
  | { name: 'targets' }
  | { name: 'reports' }
  | { name: 'audit' }
  | { name: 'debug' }

const DEV = import.meta.env.DEV

function parseHash(): Route {
  const hash = window.location.hash.replace(/^#\/?/, '')
  const [head, param] = hash.split('/')
  switch (head) {
    case 'new':
      return { name: 'new' }
    case 'runs':
      return param ? { name: 'run', id: param } : { name: 'runs' }
    case 'findings':
      return { name: 'findings' }
    case 'targets':
      return { name: 'targets' }
    case 'reports':
      return { name: 'reports' }
    case 'audit':
      return { name: 'audit' }
    case 'debug':
      return DEV ? { name: 'debug' } : { name: 'home' }
    default:
      return { name: 'home' }
  }
}

const go = (path: string) => {
  window.location.hash = path
}

const PRIMARY_NAV: { label: string; path: string; match: Route['name'][] }[] = [
  { label: 'New Assessment', path: '#/new', match: ['new'] },
  { label: 'Runs', path: '#/', match: ['home', 'runs', 'run'] },
  { label: 'Findings', path: '#/findings', match: ['findings'] },
  { label: 'Targets', path: '#/targets', match: ['targets'] },
  { label: 'Reports', path: '#/reports', match: ['reports'] },
]
const SECONDARY_NAV: { label: string; path: string; match: Route['name'][] }[] = [
  { label: 'Audit Log', path: '#/audit', match: ['audit'] },
]

function healthState(health: Health): { state: 'ok' | 'warn' | 'bad' | 'unknown'; label: string } {
  if (!health) return { state: 'unknown', label: 'Backend health unknown' }
  const control = String(health.control_plane ?? '')
  const lab = String(health.lab ?? '')
  if (control === 'HEALTHY' && lab === 'HEALTHY') return { state: 'ok', label: 'Backend healthy' }
  if (control === 'HEALTHY') return { state: 'warn', label: 'Backend degraded' }
  return { state: 'bad', label: 'Backend unavailable' }
}

export function App() {
  const [route, setRoute] = useState<Route>(parseHash())
  const [config, setConfig] = useState<ConsoleConfig>()
  const [runs, setRuns] = useState<Run[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [targets, setTargets] = useState<TargetEntry[]>([])
  const [profiles, setProfiles] = useState<AssessmentProfile[]>([])
  const [health, setHealth] = useState<Health>(null)
  const [detail, setDetail] = useState<RunDetail>()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string>()

  useEffect(() => {
    const onHash = () => setRoute(parseHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const hydrate = useCallback(async () => {
    try {
      const [cfg, runData, findingData, targetData, profileData, healthData] = await Promise.all([
        consoleApi.config(),
        consoleApi.runs(),
        consoleApi.findings(),
        consoleApi.targets(),
        consoleApi.profiles(),
        consoleApi.health(),
      ])
      setConfig(cfg)
      setRuns(runData.items)
      setFindings(findingData.items)
      setTargets(targetData.items)
      setProfiles(profileData.items)
      setHealth(healthData)
      setError(undefined)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The console could not reach the controller.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void hydrate()
  }, [hydrate])

  // Bounded refresh so active runs surface without a manual reload.
  useEffect(() => {
    const anyActive = runs.some((r) => r.status === 'RUNNING' || r.status === 'QUEUED')
    if (!anyActive) return undefined
    const timer = window.setInterval(() => {
      void consoleApi.runs().then((d) => setRuns(d.items)).catch(() => undefined)
    }, 2500)
    return () => window.clearInterval(timer)
  }, [runs])

  // Load run detail when viewing a run, and keep polling while the run is still active so the
  // operator follows real execution state through to a terminal outcome.
  const routeRunId = route.name === 'run' ? route.id : undefined
  useEffect(() => {
    if (!routeRunId) {
      setDetail(undefined)
      return undefined
    }
    let active = true
    let timer: number | undefined
    const load = () =>
      consoleApi
        .run(routeRunId)
        .then((d) => {
          if (!active) return
          setDetail(d)
          const running = d.run.status === 'RUNNING' || d.run.status === 'QUEUED'
          if (running && timer === undefined) {
            timer = window.setInterval(load, 2000)
          } else if (!running && timer !== undefined) {
            window.clearInterval(timer)
            timer = undefined
          }
        })
        .catch(() => {
          if (active) setError('Run detail could not be loaded.')
        })
    void load()
    return () => {
      active = false
      if (timer !== undefined) window.clearInterval(timer)
    }
  }, [routeRunId])

  const activeRuns = useMemo(() => runs.filter((r) => r.status === 'RUNNING' || r.status === 'QUEUED'), [runs])
  const hs = healthState(health)
  const environment = 'Synthetic Lab'

  const startAssessment = async (target: TargetEntry, profile: AssessmentProfile): Promise<Run> => {
    const cap = profile.capabilities[0]
    const native = profile.profile_id === 'aegis-native-bola-synthetic'
    return consoleApi.startAssessment({
      target: 'synthetic-bank-api',
      variant: 'vulnerable',
      capability: native ? null : cap?.capability_id,
    })
  }

  const navActive = (match: Route['name'][]) => match.includes(route.name)

  return (
    <div className="app">
      <aside className="sidebar">
        <button className="brand" onClick={() => go('#/')} aria-label="Aegis home">
          <span className="mark">A</span>
          <span className="brand-name">
            Aegis
            <span className="brand-sub">Operator Console</span>
          </span>
        </button>

        <nav className="nav-group" aria-label="Primary">
          {PRIMARY_NAV.map((item) => (
            <button
              key={item.label}
              className={`nav-item ${navActive(item.match) ? 'active' : ''}`}
              onClick={() => go(item.path)}
            >
              {item.label}
            </button>
          ))}
        </nav>

        <nav className="nav-group" aria-label="Secondary">
          <span className="nav-label">More</span>
          {SECONDARY_NAV.map((item) => (
            <button
              key={item.label}
              className={`nav-item ${navActive(item.match) ? 'active' : ''}`}
              onClick={() => go(item.path)}
            >
              {item.label}
            </button>
          ))}
          {DEV && (
            <button
              className={`nav-item ${navActive(['debug']) ? 'active' : ''}`}
              onClick={() => go('#/debug')}
            >
              Debug
            </button>
          )}
        </nav>

        <div className="sidebar-foot">
          <p className="sidebar-note">Structured, checksummed audit evidence. Synthetic lab only — not an immutable audit store.</p>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <span className="env-chip">{environment}</span>
          <HealthDot state={hs.state} label={hs.label} />
          <span className="spacer" />
          <button className="btn primary" onClick={() => go('#/new')}>
            New Assessment
          </button>
        </header>

        <main className="main">
          {error && (
            <div className="banner critical">
              <div className="banner-body">
                <strong>Console degraded</strong>
                {error} Displayed data may be stale.
              </div>
              <button className="btn" onClick={() => void hydrate()}>
                Retry
              </button>
            </div>
          )}

          {loading ? (
            <Loading />
          ) : route.name === 'new' ? (
            <NewAssessment
              targets={targets}
              profiles={profiles}
              onStart={startAssessment}
              onStarted={(run) => {
                void hydrate()
                go(`#/runs/${run.id}`)
              }}
              onCancel={() => go('#/')}
            />
          ) : route.name === 'run' ? (
            detail ? (
              <RunDetailView detail={detail} findings={findings} onBack={() => go('#/')} />
            ) : (
              <Loading label="Loading run…" />
            )
          ) : route.name === 'findings' ? (
            <FindingsView findings={findings} />
          ) : route.name === 'targets' ? (
            <TargetsView targets={targets} profiles={profiles} />
          ) : route.name === 'reports' ? (
            <ReportsView runs={runs} onOpen={(id) => go(`#/runs/${id}`)} />
          ) : route.name === 'audit' ? (
            <AuditView />
          ) : route.name === 'debug' && DEV ? (
            <DebugView health={health} config={config} />
          ) : (
            <HomeView runs={runs} activeRuns={activeRuns} onOpen={(id) => go(`#/runs/${id}`)} />
          )}
        </main>
      </div>
    </div>
  )
}

function RunsTable({ runs, onOpen }: { runs: Run[]; onOpen: (id: string) => void }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Run ID</th>
            <th>Target</th>
            <th>Assessment</th>
            <th>State</th>
            <th>Findings</th>
            <th>Started</th>
            <th>Cleanup</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => (
            <tr key={run.id} className="clickable" tabIndex={0} onClick={() => onOpen(run.id)}
              onKeyDown={(e) => e.key === 'Enter' && onOpen(run.id)}>
              <td className="mono">{short(run.id, 20)}</td>
              <td>{run.target_name}</td>
              <td>{run.engine ?? 'AEGIS_NATIVE'}</td>
              <td>
                <RunStatePill status={run.status} />
              </td>
              <td>{run.finding_count}</td>
              <td className="muted">{when(run.created_at)}</td>
              <td>
                <Pill tone="success">Complete</Pill>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function HomeView({
  runs,
  activeRuns,
  onOpen,
}: {
  runs: Run[]
  activeRuns: Run[]
  onOpen: (id: string) => void
}) {
  if (!runs.length) {
    return (
      <div>
        <div className="page-head">
          <h1>Runs</h1>
          <p>Start an assessment to see live and completed runs here.</p>
        </div>
        <Empty
          title="No assessments yet"
          copy="Run your first assessment against an authorized target. It takes about four steps."
          action={
            <button className="btn primary" onClick={() => go('#/new')}>
              New Assessment
            </button>
          }
        />
      </div>
    )
  }
  return (
    <div className="stack">
      <div className="page-head">
        <h1>Runs</h1>
        <p>Current and recent assessments.</p>
      </div>

      {activeRuns.length > 0 && (
        <div className="panel">
          <div className="panel-head">
            <h2>Active</h2>
            <Pill tone="warning" running>
              {activeRuns.length} running
            </Pill>
          </div>
          <RunsTable runs={activeRuns} onOpen={onOpen} />
        </div>
      )}

      <div className="panel">
        <div className="panel-head">
          <h2>Recent runs</h2>
          <span className="sub">{runs.length} record(s)</span>
        </div>
        <RunsTable runs={runs} onOpen={onOpen} />
      </div>
    </div>
  )
}

function FindingsView({ findings }: { findings: Finding[] }) {
  if (!findings.length)
    return (
      <div>
        <div className="page-head">
          <h1>Findings</h1>
          <p>Verifier-confirmed records only.</p>
        </div>
        <Empty
          title="No confirmed findings"
          copy="Hypotheses and incomplete evidence never appear here. Only the independent Aegis verifier can confirm a finding."
        />
      </div>
    )
  return (
    <div>
      <div className="page-head">
        <h1>Findings</h1>
        <p>Verifier-confirmed records. A hypothesis is never shown as a finding.</p>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>State</th>
              <th>Severity</th>
              <th>Finding</th>
              <th>OWASP</th>
              <th>Operation</th>
              <th>Discovery run</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => {
              const state = findingStateView(finding)
              return (
                <tr key={finding.id}>
                  <td>
                    <Pill tone={state.tone}>{state.label}</Pill>
                  </td>
                  <td>
                    <Pill tone={state.tone === 'success' ? 'success' : 'critical'}>{finding.severity}</Pill>
                  </td>
                  <td>
                    <strong>{finding.title}</strong>
                    <div className="mono muted" style={{ fontSize: 11 }}>
                      {short(finding.id, 30)}
                    </div>
                  </td>
                  <td>{finding.owasp_mapping}</td>
                  <td className="mono">{finding.affected_operation}</td>
                  <td className="mono muted">{short(finding.discovery_scan, 18)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function TargetsView({ targets, profiles }: { targets: TargetEntry[]; profiles: AssessmentProfile[] }) {
  return (
    <div>
      <div className="page-head">
        <h1>Targets</h1>
        <p>Controller-authorized inventory. Custom hostnames are not accepted in this deployment.</p>
      </div>
      <div className="stack">
        {targets.map((target) => {
          const supported = profiles.filter((p) => target.supported_profile_ids.includes(p.profile_id))
          return (
            <div className="panel" key={target.target_ref}>
              <div className="panel-head">
                <div>
                  <h2>{target.name}</h2>
                  <div className="mono muted" style={{ marginTop: 2 }}>
                    {target.target_ref}
                  </div>
                </div>
                <Pill tone="neutral">{target.environment}</Pill>
              </div>
              <p style={{ marginTop: 0 }} className="muted">
                {target.description}
              </p>
              <div className="row" style={{ marginTop: 8 }}>
                {supported.map((p) => (
                  <Pill key={p.profile_id} tone={p.available ? 'success' : 'warning'}>
                    {p.display_name}
                  </Pill>
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ReportsView({ runs, onOpen }: { runs: Run[]; onOpen: (id: string) => void }) {
  const completed = runs.filter((r) => r.status !== 'RUNNING' && r.status !== 'QUEUED')
  return (
    <div>
      <div className="page-head">
        <h1>Reports</h1>
        <p>Evidence reports for completed assessments.</p>
      </div>
      {completed.length === 0 ? (
        <Empty title="No reports yet" copy="Completed assessments produce an evidence report you can open here." />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Run ID</th>
                <th>Target</th>
                <th>Outcome</th>
                <th>Findings</th>
                <th>Completed</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {completed.map((run) => (
                <tr key={run.id} className="clickable" onClick={() => onOpen(run.id)}>
                  <td className="mono">{short(run.id, 20)}</td>
                  <td>{run.target_name}</td>
                  <td>
                    <RunStatePill status={run.status} />
                  </td>
                  <td>{run.finding_count}</td>
                  <td className="muted">{when(run.completed_at)}</td>
                  <td>
                    <span className="muted">Open report →</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

type AuditEvent = {
  event_id: string
  timestamp: string
  actor_type: string
  stage: string
  status: string
  summary: string
  scan_id: string
}

function AuditView() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [query, setQuery] = useState('')
  const [loaded, setLoaded] = useState(false)
  useEffect(() => {
    fetch('/api/console/audit?limit=100&cursor=0', { headers: { Accept: 'application/json' } })
      .then((r) => r.json())
      .then((d: { items: AuditEvent[] }) => setEvents(d.items ?? []))
      .catch(() => undefined)
      .finally(() => setLoaded(true))
  }, [])
  const filtered = events.filter((e) =>
    !query ? true : `${e.summary} ${e.scan_id} ${e.stage}`.toLowerCase().includes(query.toLowerCase()),
  )
  return (
    <div>
      <div className="page-head">
        <h1>Audit Log</h1>
        <p>Structured, checksummed, redacted event record.</p>
      </div>
      <div className="filters">
        <label className="field">
          <span>Search</span>
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="run, stage, summary…" />
        </label>
      </div>
      {!loaded ? (
        <Loading />
      ) : filtered.length === 0 ? (
        <Empty title="No events" copy="No structured audit events match this filter." />
      ) : (
        <div className="panel">
          {filtered
            .slice()
            .reverse()
            .map((event) => (
              <div className="activity-item" key={event.event_id}>
                <time>{new Date(event.timestamp).toLocaleTimeString()}</time>
                <Pill tone={event.actor_type === 'VERIFIER' ? 'success' : 'neutral'}>
                  {event.actor_type.replace('_', ' ')}
                </Pill>
                <span className="summary">
                  {event.stage.replaceAll('_', ' ')} — {event.summary}
                </span>
                <span className="addr mono">{short(event.scan_id, 14)}</span>
              </div>
            ))}
        </div>
      )}
    </div>
  )
}

function DebugView({ health, config }: { health: Health; config?: ConsoleConfig }) {
  return (
    <div>
      <div className="page-head">
        <h1>Debug</h1>
        <p>Development-only diagnostics. Not part of the operator workflow.</p>
      </div>
      <div className="grid-2">
        <div className="panel">
          <div className="panel-head">
            <h3>Operational engines</h3>
          </div>
          <div className="row">
            {(config?.operational_engines ?? []).map((engine) => (
              <Pill key={engine} tone="success">
                {engine}
              </Pill>
            ))}
          </div>
        </div>
        <div className="panel">
          <div className="panel-head">
            <h3>Subsystem health</h3>
          </div>
          <Kv
            items={Object.entries(health ?? {})
              .filter(([, v]) => typeof v === 'string')
              .map(([k, v]) => [k.replaceAll('_', ' '), String(v)])}
          />
        </div>
      </div>
    </div>
  )
}
