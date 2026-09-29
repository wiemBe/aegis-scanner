import { useEffect, useMemo, useRef, useState } from 'react'
import type {
  AssessmentProfile,
  BeastConfig,
  BeastPreflight,
  BeastRunView,
  TargetEntry,
} from './api'
import { consoleApi } from './api'
import { Kv, Loading, Pill } from './components'
import type { Tone } from './format'

const TERMINAL_STATES = new Set(['VERIFIED', 'PASS', 'REVIEW_REQUIRED', 'INCOMPLETE', 'STOPPED'])

type CampaignItem = {
  profile: AssessmentProfile
  scenario: string
  state: 'PENDING' | 'STARTING' | string
  runId?: string
  detail?: BeastRunView
  error?: string
}

function tone(state: string): Tone {
  if (state === 'PASS') return 'success'
  if (state === 'RUNNING' || state === 'QUEUED' || state === 'STARTING') return 'warning'
  if (state === 'VERIFIED') return 'critical'
  return 'neutral'
}

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms))
}

export function ToolboxCampaign({
  target,
  profiles,
  scenarios,
  onBack,
}: {
  target: TargetEntry
  profiles: AssessmentProfile[]
  scenarios: Record<string, string>
  onBack: () => void
}) {
  const [config, setConfig] = useState<BeastConfig>()
  const [preflight, setPreflight] = useState<BeastPreflight>()
  const [loading, setLoading] = useState(true)
  const [operatorId, setOperatorId] = useState('')
  const [phrase, setPhrase] = useState('')
  const [requestBudget, setRequestBudget] = useState('')
  const [durationMinutes, setDurationMinutes] = useState('')
  const [items, setItems] = useState<CampaignItem[]>(() => profiles.map((profile) => ({
    profile,
    scenario: scenarios[profile.profile_id] ?? '',
    state: 'PENDING',
  })))
  const [running, setRunning] = useState(false)
  const [complete, setComplete] = useState(false)
  const [error, setError] = useState<string>()
  const currentRunRef = useRef<string | undefined>(undefined)
  const stopRequestedRef = useRef(false)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    Promise.all([consoleApi.beastConfig(), consoleApi.beastPreflight(target.target_ref)])
      .then(([nextConfig, nextPreflight]) => {
        if (!mountedRef.current) return
        setConfig(nextConfig)
        setPreflight(nextPreflight)
        setRequestBudget(String(nextPreflight.resources.max_target_connections))
        setDurationMinutes(String(nextPreflight.resources.total_wall_time_seconds / 60))
      })
      .catch((reason) => {
        if (mountedRef.current) {
          setError(reason instanceof Error ? reason.message : 'Campaign preflight was rejected.')
        }
      })
      .finally(() => {
        if (mountedRef.current) setLoading(false)
      })
    return () => {
      mountedRef.current = false
    }
  }, [target.target_ref])

  const requiredPhrase = preflight ? `ASSESS ${preflight.target.name}` : ''
  const operatorOk = /^[A-Za-z0-9._@-]{3,80}$/.test(operatorId)
  const phraseOk = phrase.trim() === requiredPhrase && requiredPhrase !== ''
  const requestBudgetValue = Number(requestBudget)
  const durationSeconds = Math.round(Number(durationMinutes) * 60)
  const resourcesOk = Boolean(
    preflight &&
    Number.isInteger(requestBudgetValue) &&
    requestBudgetValue >= 1 &&
    requestBudgetValue <= preflight.resources.max_target_connections &&
    Number.isFinite(durationSeconds) &&
    durationSeconds >= 10 &&
    durationSeconds <= preflight.resources.total_wall_time_seconds,
  )
  const campaignValid = profiles.length > 1 && profiles.every(
    (profile) => profile.available && profile.engine === 'TOOLBOX' && Boolean(scenarios[profile.profile_id]),
  )
  const canStart = Boolean(config?.enabled && preflight && campaignValid && operatorOk && phraseOk && resourcesOk && !running)
  const completedCount = useMemo(
    () => items.filter((item) => TERMINAL_STATES.has(item.state)).length,
    [items],
  )

  const updateItem = (index: number, patch: Partial<CampaignItem>) => {
    if (!mountedRef.current) return
    setItems((current) => current.map((item, itemIndex) => (
      itemIndex === index ? { ...item, ...patch } : item
    )))
  }

  const start = async () => {
    if (!config || !preflight || !canStart) return
    setRunning(true)
    setComplete(false)
    setError(undefined)
    stopRequestedRef.current = false
    setItems(profiles.map((profile) => ({
      profile,
      scenario: scenarios[profile.profile_id] ?? '',
      state: 'PENDING',
    })))

    for (let index = 0; index < profiles.length; index += 1) {
      if (stopRequestedRef.current || !mountedRef.current) break
      const profile = profiles[index]
      if (!profile) continue
      const scenario = scenarios[profile.profile_id]
      if (!scenario) {
        updateItem(index, { state: 'INCOMPLETE', error: 'No controller-bound scenario.' })
        continue
      }
      updateItem(index, { state: 'STARTING' })
      try {
        const lease = await consoleApi.beastIssueLease({
          operator_id: operatorId,
          actor_type: 'OPERATOR',
          target_ref: target.target_ref,
          profile_id: config.profile_id,
          operator_profile_id: profile.profile_id,
          confirmation: phrase.trim(),
          requested_resources: {
            ...preflight.resources,
            max_target_connections: requestBudgetValue,
            total_wall_time_seconds: durationSeconds,
          },
        })
        const created = await consoleApi.beastCreateRun({ lease_id: lease.lease_id, scenario_id: scenario })
        currentRunRef.current = created.run_id
        updateItem(index, { state: created.state, runId: created.run_id, detail: created })

        let latest = created
        while (!TERMINAL_STATES.has(latest.state) && !stopRequestedRef.current && mountedRef.current) {
          await pause(1500)
          const detail = await consoleApi.beastRun(created.run_id)
          latest = detail.run
          updateItem(index, { state: latest.state, detail: latest })
        }
      } catch (reason) {
        updateItem(index, {
          state: 'INCOMPLETE',
          error: reason instanceof Error ? reason.message : 'The controller rejected this scan.',
        })
      } finally {
        currentRunRef.current = undefined
      }
    }

    if (mountedRef.current) {
      setRunning(false)
      setComplete(!stopRequestedRef.current)
    }
  }

  const stop = async () => {
    stopRequestedRef.current = true
    const runId = currentRunRef.current
    if (runId && operatorOk) {
      try {
        await consoleApi.beastStop(runId, operatorId)
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : 'Emergency stop failed.')
      }
    }
    if (mountedRef.current) setRunning(false)
  }

  if (loading) return <Loading label="Loading complete assessment preflight…" />

  return (
    <div className="stack campaign-shell">
      <div className="page-head campaign-head">
        <div>
          <span className="section-kicker">Multi-scan mode</span>
          <h1>Complete toolbox assessment</h1>
          <p>Runs all compatible templates sequentially against one authorized target.</p>
        </div>
        <button className="btn ghost" onClick={onBack} disabled={running}>← Back to templates</button>
      </div>

      {error && <div className="banner critical"><div className="banner-body"><strong>Campaign error</strong>{error}</div></div>}
      {!config?.enabled && (
        <div className="banner critical"><div className="banner-body">
          <strong>The disposable toolbox is unavailable.</strong>
          Start the full-lab stack before running this campaign.
        </div></div>
      )}

      <div className="campaign-layout">
        <main className="stack">
          <section className="panel">
            <div className="panel-head">
              <div><h2>Campaign authorization</h2><span className="sub">One target · {profiles.length} profile-bound leases</span></div>
              <Pill tone="warning">Sequential</Pill>
            </div>
            {preflight && <Kv items={[
              ['Target', preflight.target.name],
              ['Authorized path', preflight.target.allowed_path_prefix],
              ['Allowed methods', preflight.target.allowed_methods.join(', ')],
              ['Emergency stop', preflight.emergency_stop],
            ]} />}
            <div className="filters campaign-controls">
              <label className="field">
                <span>Operator ID</span>
                <input value={operatorId} onChange={(event) => setOperatorId(event.target.value)} placeholder="e.g. operator-1" disabled={running} />
              </label>
              <label className="field">
                <span>Connection budget per scan</span>
                <input type="number" value={requestBudget} onChange={(event) => setRequestBudget(event.target.value)} disabled={running} />
              </label>
              <label className="field">
                <span>Maximum minutes per scan</span>
                <input type="number" step="0.1" value={durationMinutes} onChange={(event) => setDurationMinutes(event.target.value)} disabled={running} />
              </label>
            </div>
            <label className="field wide campaign-confirmation">
              <span>Type <code className="mono">{requiredPhrase}</code> to authorize all {profiles.length} bounded scans</span>
              <input value={phrase} onChange={(event) => setPhrase(event.target.value)} autoComplete="off" disabled={running} />
            </label>
            <div className="campaign-actions">
              {running ? (
                <button className="btn danger lg" onClick={() => void stop()}>⏹ Stop campaign</button>
              ) : (
                <button className="btn primary lg" disabled={!canStart} onClick={() => void start()}>
                  {complete ? 'Run complete assessment again' : `Start all ${profiles.length} scans`}
                </button>
              )}
            </div>
          </section>
        </main>

        <aside className="panel campaign-queue">
          <div className="panel-head">
            <div><h2>Scan queue</h2><span className="sub">{completedCount}/{profiles.length} completed</span></div>
          </div>
          {items.map((item, index) => (
            <div className="campaign-item" key={item.profile.profile_id}>
              <span className="campaign-index">{index + 1}</span>
              <div>
                <strong>{item.profile.display_name}</strong>
                <small>{item.profile.tools?.join(' · ') || item.profile.engine}</small>
                {item.runId && <small className="mono">{item.runId}</small>}
                {item.error && <small className="critical-text">{item.error}</small>}
              </div>
              <Pill tone={tone(item.state)} running={item.state === 'RUNNING'}>{item.state}</Pill>
            </div>
          ))}
        </aside>
      </div>
    </div>
  )
}
