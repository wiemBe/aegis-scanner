import { useMemo, useRef, useState } from 'react'
import type { AssessmentProfile, Run, TargetEntry } from './api'
import { consoleApi } from './api'
import { Pill } from './components'
import type { Tone } from './format'

const TERMINAL_STATES = new Set<Run['status']>(['PASS', 'FAIL', 'REVIEW', 'INCOMPLETE'])

type CampaignItem = {
  profile: AssessmentProfile
  state: 'PENDING' | 'STARTING' | Run['status']
  runId?: string
  error?: string
}

type StartAssessment = (
  target: TargetEntry,
  profile: AssessmentProfile,
  limits: { request_budget: number; max_duration_minutes: number },
) => Promise<{ run_id: string }>

function tone(state: CampaignItem['state']): Tone {
  if (state === 'PASS') return 'success'
  if (state === 'FAIL') return 'critical'
  if (state === 'RUNNING' || state === 'QUEUED' || state === 'STARTING') return 'warning'
  return 'neutral'
}

function pause(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms))
}

function profileLimits(profile: AssessmentProfile) {
  const requestBudget = profile.capabilities.reduce(
    (maximum, capability) => Math.max(maximum, capability.request_budget),
    0,
  )
  const timeBudgetMs = profile.capabilities.reduce(
    (maximum, capability) => Math.max(maximum, capability.time_budget_ms),
    0,
  )
  return {
    request_budget: requestBudget,
    max_duration_minutes: timeBudgetMs / 60_000,
  }
}

export function StandardCampaign({
  target,
  profiles,
  onStart,
  onOpenRun,
  onBack,
}: {
  target: TargetEntry
  profiles: AssessmentProfile[]
  onStart: StartAssessment
  onOpenRun: (runId: string) => void
  onBack: () => void
}) {
  const [items, setItems] = useState<CampaignItem[]>(() => profiles.map((profile) => ({
    profile,
    state: 'PENDING',
  })))
  const [running, setRunning] = useState(false)
  const [complete, setComplete] = useState(false)
  const stopRequested = useRef(false)

  const completedCount = useMemo(
    () => items.filter((item) => TERMINAL_STATES.has(item.state as Run['status'])).length,
    [items],
  )

  const updateItem = (index: number, patch: Partial<CampaignItem>) => {
    setItems((current) => current.map((item, itemIndex) => (
      itemIndex === index ? { ...item, ...patch } : item
    )))
  }

  const start = async () => {
    if (running) return
    setRunning(true)
    setComplete(false)
    stopRequested.current = false
    setItems(profiles.map((profile) => ({ profile, state: 'PENDING' })))

    for (let index = 0; index < profiles.length; index += 1) {
      if (stopRequested.current) break
      const profile = profiles[index]
      if (!profile) continue
      updateItem(index, { state: 'STARTING', error: undefined })
      try {
        const created = await onStart(target, profile, profileLimits(profile))
        updateItem(index, { state: 'QUEUED', runId: created.run_id })
        let detail = await consoleApi.run(created.run_id)
        updateItem(index, { state: detail.run.status })
        while (!TERMINAL_STATES.has(detail.run.status) && !stopRequested.current) {
          await pause(1500)
          detail = await consoleApi.run(created.run_id)
          updateItem(index, { state: detail.run.status })
        }
      } catch (reason) {
        updateItem(index, {
          state: 'INCOMPLETE',
          error: reason instanceof Error ? reason.message : 'The controller rejected this scan.',
        })
      }
    }

    setRunning(false)
    setComplete(!stopRequested.current)
  }

  const stop = () => {
    stopRequested.current = true
    setRunning(false)
  }

  return (
    <div className="stack campaign-shell">
      <div className="page-head campaign-head">
        <div>
          <span className="section-kicker">Multi-scan mode</span>
          <h1>Complete assessment</h1>
          <p>Runs every compatible scan template sequentially against one authorized target.</p>
        </div>
        <button className="btn ghost" onClick={onBack} disabled={running}>← Back to templates</button>
      </div>

      <div className="campaign-layout">
        <main className="stack">
          <section className="panel">
            <div className="panel-head">
              <div><h2>Campaign plan</h2><span className="sub">One target · {profiles.length} controller-governed scans</span></div>
              <Pill tone="warning">Sequential</Pill>
            </div>
            <div className="config-fact-list">
              <div><span>Target</span><strong>{target.name}</strong></div>
              <div><span>Authorized scope</span><strong className="mono">{target.authorized_scope.join(', ')}</strong></div>
              <div><span>Authorization</span><strong>{target.authorization_reference}</strong></div>
              <div><span>Execution</span><strong>One isolated run per template</strong></div>
            </div>
            <div className="banner warning execution-warning">
              <div className="banner-body">
                <strong>Bounded campaign</strong>
                Each scan keeps its own controller policy, request ceiling and timeout. A failed scan is recorded and the queue continues.
              </div>
            </div>
            <div className="campaign-actions">
              {running ? (
                <button className="btn danger lg" onClick={stop}>Stop after current scan</button>
              ) : (
                <button className="btn primary lg" onClick={() => void start()}>
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
                {item.runId && (
                  <button className="campaign-run-link mono" onClick={() => onOpenRun(item.runId!)}>
                    {item.runId}
                  </button>
                )}
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
