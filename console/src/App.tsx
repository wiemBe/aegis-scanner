import { useCallback, useEffect, useMemo, useState } from 'react'
import type {
  AiBalance,
  AiModelCatalog,
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
import { AddTarget } from './AddTarget'
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

function balanceText(balance: AiBalance): string {
  if (balance.state === 'UNSUPPORTED') return 'Balance n/a'
  if (balance.state !== 'AVAILABLE') return 'Balance unavailable'
  if (balance.balances.length === 0 && balance.provider === 'openrouter' && balance.total_usage) {
    return `Used USD ${Number(balance.total_usage).toLocaleString(undefined, { maximumFractionDigits: 4 })} · no key cap`
  }
  if (balance.balances.length === 0) return 'Balance unavailable'
  return balance.balances
    .map((entry) => `${entry.currency} ${Number(entry.remaining).toLocaleString(undefined, { maximumFractionDigits: 4 })}`)
    .join(' · ')
}

function aiModelLabel(model: string): string {
  const labels: Record<string, string> = {
    'qwen/qwen3.8-27b': 'Qwen 3.8 27B',
    'deepseek/deepseek-v4-flash': 'DeepSeek V4 Flash',
    'z-ai/glm-5.3': 'GLM 5.3',
    'z-ai/glm-5.3-flash': 'GLM 5.3 Flash',
    'z-ai/glm-5.3-flashx': 'GLM 5.3 FlashX',
    'z-ai/glm-5.3-prime': 'GLM 5.3 Prime',
  }
  return labels[model] ? `${labels[model]} · OpenRouter` : model
}

export function App() {
  const [route, setRoute] = useState<Route>(parseHash())
  const [config, setConfig] = useState<ConsoleConfig>()
  const [aiCatalog, setAiCatalog] = useState<AiModelCatalog>()
  const [aiBalance, setAiBalance] = useState<AiBalance>()
  const [aiBusy, setAiBusy] = useState<'select' | 'test' | undefined>()
  const [balanceBusy, setBalanceBusy] = useState(false)
  const [aiNotice, setAiNotice] = useState<{ ok: boolean; text: string }>()
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
      const [cfg, aiData, balanceData, runData, findingData, targetData, profileData, healthData] = await Promise.all([
        consoleApi.config(),
        // Model-provider availability must not take the operator console down with it. Targets,
        // profiles and completed evidence remain usable when a paid provider is out of credit or
        // its gateway is offline; the model switcher simply stays hidden until it recovers.
        consoleApi.aiModels().catch(() => undefined),
        consoleApi.aiBalance().catch(() => undefined),
        consoleApi.runs(),
        consoleApi.findings(),
        consoleApi.targets(),
        consoleApi.profiles(),
        consoleApi.health(),
      ])
      setConfig(cfg)
      setAiCatalog(aiData)
      setAiBalance(balanceData)
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
  const environment = 'Authorized Assessment'

  const startAssessment = async (
    target: TargetEntry,
    profile: AssessmentProfile,
    limits: { request_budget: number; max_duration_minutes: number },
  ) => {
    // Typed controller job referencing the stable inventory target id. The controller enforces the
    // target's stored scope; the browser never sends an origin or a scanner argument.
    return consoleApi.startAssessment({
      target_id: target.target_ref,
      profile_id: profile.profile_id,
      ...limits,
    })
  }

  const refreshAiBalance = async () => {
    setBalanceBusy(true)
    try {
      setAiBalance(await consoleApi.aiBalance())
    } catch {
      setAiBalance((current) => current ? { ...current, state: 'UNAVAILABLE', balances: [] } : undefined)
    } finally {
      setBalanceBusy(false)
    }
  }

  const onTargetCreated = (created: TargetEntry) => {
    setTargets((current) => [...current, created])
  }

  const selectAiModel = async (model: string) => {
    if (!aiCatalog || model === aiCatalog.current_model) return
    setAiBusy('select')
    setAiNotice(undefined)
    try {
      const updated = await consoleApi.selectAiModel(model)
      setAiCatalog(updated)
      setAiNotice({ ok: true, text: `${updated.current_model} selected` })
    } catch (reason) {
      setAiNotice({
        ok: false,
        text: reason instanceof Error ? reason.message : 'Model change was rejected.',
      })
    } finally {
      setAiBusy(undefined)
    }
  }

  const testAi = async () => {
    setAiBusy('test')
    setAiNotice(undefined)
    try {
      const result = await consoleApi.testAi()
      setAiNotice({
        ok: result.status === 'PASS' && result.cleanup_verified,
        text:
          result.status === 'PASS'
            ? `AI test passed · fixture ${result.fixture_state.toLowerCase()} · no Docker resources`
            : `AI test failed: ${result.code} · fixture ${result.fixture_state.toLowerCase()}`,
      })
    } catch (reason) {
      setAiNotice({
        ok: false,
        text: reason instanceof Error ? reason.message : 'AI test could not run.',
      })
    } finally {
      setAiBusy(undefined)
    }
  }

  // The floating status notice is a transient toast: it auto-dismisses instead of sitting on top
  // of the page content indefinitely.
  useEffect(() => {
    if (!aiNotice) return undefined
    const timer = window.setTimeout(() => setAiNotice(undefined), 7000)
    return () => window.clearTimeout(timer)
  }, [aiNotice])

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
          <p className="sidebar-note">Structured, checksummed audit evidence for explicitly authorized targets. Not an immutable audit store.</p>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <span className="env-chip">{environment}</span>
          <HealthDot state={hs.state} label={hs.label} />
          <span className="spacer" />
          {aiCatalog && Array.isArray(aiCatalog.models) && (
            <div className="ai-switcher">
              <span className="ai-provider">{aiCatalog.provider}</span>
              {aiBalance?.state && (
                <button
                  type="button"
                  className={`ai-balance ${aiBalance.state.toLowerCase()}`}
                  onClick={() => void refreshAiBalance()}
                  disabled={balanceBusy}
                  title="Refresh provider balance"
                >
                  {balanceBusy ? 'Balance…' : balanceText(aiBalance)}
                </button>
              )}
              <label className="sr-only" htmlFor="ai-model-select">AI model</label>
              <select
                id="ai-model-select"
                aria-label="AI model"
                title={aiModelLabel(aiCatalog.current_model)}
                value={aiCatalog.current_model}
                disabled={Boolean(aiBusy) || aiCatalog.models.length === 0}
                onChange={(event) => void selectAiModel(event.target.value)}
              >
                {aiCatalog.models.map((model) => (
                  <option key={model} value={model}>{aiModelLabel(model)}</option>
                ))}
              </select>
              <button className="btn" disabled={Boolean(aiBusy)} onClick={() => void testAi()}>
                {aiBusy === 'test' ? 'Testing…' : 'Test AI'}
              </button>
              {aiNotice && (
                <span className={`ai-notice ${aiNotice.ok ? 'ok' : 'bad'}`} role="status">
                  {aiNotice.text}
                </span>
              )}
            </div>
          )}
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
              onStarted={(runId) => {
                void hydrate()
                go(`#/runs/${runId}`)
              }}
              onTargetCreated={onTargetCreated}
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
            <TargetsView
              targets={targets}
              profiles={profiles}
              onTargetCreated={onTargetCreated}
              onTargetUpdated={(t) =>
                setTargets((current) => current.map((c) => (c.target_ref === t.target_ref ? t : c)))
              }
              onTargetDeleted={(targetRef) =>
                setTargets((current) => current.filter((target) => target.target_ref !== targetRef))
              }
            />
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
      <div className="page-head with-action">
        <div>
          <h1>Runs</h1>
          <p>Current and recent assessments.</p>
        </div>
        <a className="btn" href="/api/console/runs.csv" download>
          Export CSV
        </a>
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

function TargetsView({
  targets,
  profiles,
  onTargetCreated,
  onTargetUpdated,
  onTargetDeleted,
}: {
  targets: TargetEntry[]
  profiles: AssessmentProfile[]
  onTargetCreated: (t: TargetEntry) => void
  onTargetUpdated: (t: TargetEntry) => void
  onTargetDeleted: (targetRef: string) => void
}) {
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<TargetEntry>()
  const [detail, setDetail] = useState<TargetEntry>()
  const [deleting, setDeleting] = useState<TargetEntry>()
  const [deleteConfirmation, setDeleteConfirmation] = useState('')
  const [deleteError, setDeleteError] = useState<string>()
  const [busy, setBusy] = useState<string>()

  const openDelete = (target: TargetEntry) => {
    setDeleteConfirmation('')
    setDeleteError(undefined)
    setDeleting(target)
  }

  const remove = async () => {
    if (!deleting || deleteConfirmation !== deleting.name || busy) return
    setBusy(deleting.target_ref)
    setDeleteError(undefined)
    try {
      await consoleApi.deleteTarget(deleting.target_ref)
      onTargetDeleted(deleting.target_ref)
      if (detail?.target_ref === deleting.target_ref) setDetail(undefined)
      if (editing?.target_ref === deleting.target_ref) setEditing(undefined)
      setDeleting(undefined)
      setDeleteConfirmation('')
    } catch (reason) {
      setDeleteError(reason instanceof Error ? reason.message : 'The target could not be deleted.')
    } finally {
      setBusy(undefined)
    }
  }

  const toggle = async (target: TargetEntry) => {
    setBusy(target.target_ref)
    try {
      const updated = target.enabled
        ? await consoleApi.disableTarget(target.target_ref)
        : await consoleApi.enableTarget(target.target_ref)
      onTargetUpdated(updated)
    } catch {
      /* transient; the controller remains the source of truth on next hydrate */
    } finally {
      setBusy(undefined)
    }
  }

  const kind = (t: TargetEntry) =>
    t.synthetic ? (
      <Pill tone="neutral">Synthetic</Pill>
    ) : t.environment.toUpperCase().includes('PRODUCTION') ? (
      <Pill tone="warning">Production</Pill>
    ) : (
      <Pill tone="success">Company</Pill>
    )

  // A user-onboarded synthetic target is still mutable. The immutable distinction is catalog seed
  // versus operator inventory, not merely whether the target environment is synthetic.
  const operatorOwned = (target: TargetEntry) =>
    target.origin_source === 'OPERATOR_ONBOARDED' || !target.synthetic

  return (
    <div>
      <div className="page-head with-action">
        <div>
          <h1>Targets</h1>
          <p>Controller-authorized inventory. Onboard company websites, APIs and authorized ranges.</p>
        </div>
        <button className="btn primary" onClick={() => setAdding(true)}>
          + Add authorized target
        </button>
      </div>

      {targets.length === 0 ? (
        <Empty
          title="No targets yet"
          copy="Add an authorized company website, API or range to assess."
          action={<button className="btn primary" onClick={() => setAdding(true)}>Add authorized target</button>}
        />
      ) : (
        <div className="table-wrap">
          <table className="targets-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Authorized scope</th>
                <th>Environment</th>
                <th>Authorization</th>
                <th>Last assessment</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {targets.map((target) => (
                <tr key={target.target_ref}>
                  <td>
                    <strong>{target.name}</strong>
                    <div className="mono muted" style={{ fontSize: 11 }}>{target.target_ref}</div>
                  </td>
                  <td>{kind(target)}</td>
                  <td className="mono">
                    {target.authorized_scope.slice(0, 2).map((s) => (
                      <div key={s}>{s}</div>
                    ))}
                    {target.authorized_scope.length > 2 && (
                      <div className="muted">+{target.authorized_scope.length - 2} more</div>
                    )}
                  </td>
                  <td>{target.environment.replaceAll('_', ' ')}</td>
                  <td>
                    <Pill tone={target.status === 'AVAILABLE_FOR_ASSESSMENT' ? 'success' : 'neutral'}>
                      {target.status === 'AVAILABLE_FOR_ASSESSMENT' ? 'Available' : target.status.replaceAll('_', ' ')}
                    </Pill>
                  </td>
                  <td className="muted">{target.last_assessment_at ? when(target.last_assessment_at) : '—'}</td>
                  <td>
                    <Pill tone={target.enabled ? 'success' : 'warning'}>
                      {target.enabled ? 'Enabled' : 'Disabled'}
                    </Pill>
                  </td>
                  <td className="target-actions">
                    <button className="link-btn" onClick={() => setDetail(target)}>View</button>
                    {operatorOwned(target) ? (
                      <>
                        <button className="link-btn" onClick={() => setEditing(target)}>Edit</button>
                        <button
                          className="link-btn"
                          disabled={busy === target.target_ref}
                          onClick={() => void toggle(target)}
                        >
                          {target.enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          className="link-btn destructive"
                          disabled={busy === target.target_ref}
                          onClick={() => openDelete(target)}
                        >
                          Delete
                        </button>
                      </>
                    ) : (
                      // A catalog-seeded target is controller-defined and immutable. The row says so
                      // instead of silently hiding the edit affordance.
                      <span
                        className="immutable-note"
                        title="Catalog-seeded targets are controller-defined and immutable. Onboard a target with '+ Add authorized target' to edit its authorized scope here."
                      >
                        Immutable
                      </span>
                    )}
                    <button
                      className="link-btn"
                      disabled={!target.enabled}
                      onClick={() => go('#/new')}
                    >
                      Start assessment
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {detail && (
        <div className="modal-scrim" role="dialog" aria-modal="true" onClick={() => setDetail(undefined)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="panel-head">
              <h2>{detail.name}</h2>
              {kind(detail)}
            </div>
            <p className="muted">{detail.description || 'No description.'}</p>
            <Kv
              items={[
                ['Target ID', <span className="mono" key="id">{detail.target_ref}</span>],
                ['Type', detail.type],
                ['Environment', detail.environment],
                ['Authorization ref', <span className="mono" key="a">{detail.authorization_reference}</span>],
                ['Authorized scope', detail.authorized_scope.map((s) => <div className="mono" key={s}>{s}</div>)],
                ['Allowed paths', detail.allowed_path_prefixes.join(', ') || '— (all)'],
                ['Excluded paths', detail.excluded_path_prefixes.join(', ') || '—'],
                ['Credential', detail.credential_reference ? <span className="mono" key="c">{detail.credential_reference}</span> : 'None referenced'],
                ['Compatible profiles', profiles.filter((p) => detail.supported_profile_ids.includes(p.profile_id)).map((p) => p.display_name).join(', ') || '—'],
              ]}
            />
            <div className="modal-actions">
              {operatorOwned(detail) ? (
                <>
                  <button className="btn" onClick={() => {
                    setEditing(detail)
                    setDetail(undefined)
                  }}>Edit</button>
                  <button className="btn danger" onClick={() => {
                    openDelete(detail)
                    setDetail(undefined)
                  }}>Delete</button>
                </>
              ) : (
                <p className="immutable-note modal-note">
                  Catalog-seeded target — immutable. Only operator-onboarded targets can be edited or deleted.
                </p>
              )}
              <button className="btn ghost" onClick={() => setDetail(undefined)}>Close</button>
            </div>
          </div>
        </div>
      )}

      {adding && (
        <AddTarget
          onClose={() => setAdding(false)}
          onCreated={(created) => {
            onTargetCreated(created)
            setAdding(false)
          }}
        />
      )}

      {editing && (
        <AddTarget
          editTarget={editing}
          onClose={() => setEditing(undefined)}
          onCreated={() => setEditing(undefined)}
          onUpdated={(updated) => {
            onTargetUpdated(updated)
            setEditing(undefined)
          }}
        />
      )}

      {deleting && (
        <div className="modal-scrim" role="dialog" aria-modal="true" aria-label="Delete authorized target">
          <div className="modal">
            <h2>Delete authorized target</h2>
            <p>
              This removes <strong>{deleting.name}</strong> from the authorized inventory. Existing
              assessment reports and evidence are retained, but no new assessment can use this target.
            </p>
            <label className="field wide">
              <span>Type <strong>{deleting.name}</strong> to confirm</span>
              <input
                autoFocus
                value={deleteConfirmation}
                onChange={(event) => setDeleteConfirmation(event.target.value)}
                aria-label="Target name confirmation"
                autoComplete="off"
              />
            </label>
            {deleteError && (
              <div className="banner critical">
                <div className="banner-body"><strong>Delete failed</strong>{deleteError}</div>
              </div>
            )}
            <div className="modal-actions">
              <button
                className="btn ghost"
                disabled={busy === deleting.target_ref}
                onClick={() => setDeleting(undefined)}
              >
                Cancel
              </button>
              <button
                className="btn danger"
                disabled={deleteConfirmation !== deleting.name || busy === deleting.target_ref}
                onClick={() => void remove()}
              >
                {busy === deleting.target_ref ? 'Deleting…' : 'Delete target'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function ReportsView({ runs, onOpen }: { runs: Run[]; onOpen: (id: string) => void }) {
  const completed = runs.filter((r) => r.status !== 'RUNNING' && r.status !== 'QUEUED')
  return (
    <div>
      <div className="page-head with-action">
        <div>
          <h1>Reports</h1>
          <p>Evidence reports for completed assessments.</p>
        </div>
        <a className="btn" href="/api/console/runs.csv" download>
          Export CSV
        </a>
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
