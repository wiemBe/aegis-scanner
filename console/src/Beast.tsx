import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type {
  BeastCommand,
  BeastConfig,
  BeastEvent,
  BeastModelCall,
  BeastObservation,
  BeastPreflight,
  BeastRunView,
} from './api'
import { consoleApi } from './api'
import { Kv, Loading, Pill } from './components'
import type { Tone } from './format'

type Turn = {
  call: BeastModelCall
  command?: BeastCommand
  observation?: BeastObservation
  stop?: { hypothesis?: string; summary?: string; evidence_observation_ids?: string[] }
  inputs: BeastObservation[]
}

function buildTurns(run: BeastRunView, events: BeastEvent[]): Turn[] {
  const byId = new Map(run.observations.map((o) => [o.observation_id, o]))
  const stopEvent = events.find((e) => e.event_type === 'AI_ADVERSARY_STOPPED')
  return run.model_calls
    .slice()
    .sort((a, b) => a.sequence - b.sequence)
    .map((call) => ({
      call,
      command: run.commands.find((c) => c.sequence === call.sequence),
      observation: run.observations.find((o) => o.sequence === call.sequence),
      stop: call.decision_type === 'stop' ? (stopEvent?.details as Turn['stop']) : undefined,
      inputs: call.input_observation_ids.map((id) => byId.get(id)).filter((o): o is BeastObservation => Boolean(o)),
    }))
}

function tokens(call: BeastModelCall): string {
  const u = call.usage ?? {}
  const total = u.total_tokens ?? (Number(u.input_tokens ?? 0) + Number(u.output_tokens ?? 0))
  const meta = call.metadata ?? {}
  const inTok = u.input_tokens ?? meta.prompt_eval_count
  const outTok = u.output_tokens ?? meta.eval_count
  return `${total || '—'} tok (in ${inTok ?? '—'} / out ${outTok ?? '—'})`
}

// Internal implementation of the autonomous toolbox assessment. The operator sees it as a normal
// assessment profile; the disposable sandbox remains an execution boundary, not a separate mode.

const SCENARIO_LABELS: Record<string, string> = {
  endpoint_discovery: 'Endpoint discovery',
  information_exposure: 'Information exposure (source-control metadata)',
  bola_readonly: 'Read-only BOLA (cross-owner object read)',
  safe_injection: 'Safe injection probe (non-destructive)',
}

const TERMINAL_STATES = new Set(['VERIFIED', 'PASS', 'REVIEW_REQUIRED', 'INCOMPLETE', 'STOPPED'])

function stateTone(state: string): Tone {
  if (state === 'VERIFIED') return 'critical'
  if (state === 'PASS') return 'success'
  if (state === 'RUNNING' || state === 'QUEUED') return 'warning'
  if (state === 'STOPPED') return 'critical'
  return 'neutral'
}

function verifierTone(status: string): Tone {
  if (status === 'CONFIRMED' || status === 'VERIFIED') return 'critical'
  if (status === 'PASS') return 'success'
  return 'neutral'
}

function clip(text: string, max = 1500): string {
  if (!text) return ''
  return text.length > max ? `${text.slice(0, max)}\n…[truncated ${text.length - max} chars]` : text
}

function TranscriptTurn({
  turn,
  objectiveLabel,
  targetLine,
}: {
  turn: Turn
  objectiveLabel: string
  targetLine: string
}) {
  const { call, command, observation, stop, inputs } = turn
  const isStop = call.decision_type === 'stop'
  const duration = Number(call.metadata?.total_duration_ms ?? 0)
  const facts = observation?.facts ?? {}
  const factKeys = Object.keys(facts)

  return (
    <div className="turn">
      <div className="turn-head">
        <strong>Turn {call.sequence}</strong>
        <Pill tone={isStop ? 'success' : 'neutral'}>{isStop ? 'STOP' : 'COMMAND'}</Pill>
        <span className="sub mono">{tokens(call)}</span>
        {duration > 0 && <span className="sub mono">{duration} ms</span>}
      </div>

      {/* Input the model received for this turn. */}
      <div className="io input">
        <span className="io-label">SENT TO MODEL</span>
        <div className="io-body">
          <div className="io-line">
            <span className="muted">Objective:</span> {objectiveLabel}
          </div>
          {targetLine && (
            <div className="io-line">
              <span className="muted">Target:</span> <span className="mono">{targetLine}</span>
            </div>
          )}
          {inputs.length === 0 ? (
            <div className="io-line muted">No prior observations — first turn, started from the target origin.</div>
          ) : (
            <div className="io-line">
              <span className="muted">Prior observations provided ({inputs.length}):</span>
              <ul className="io-list">
                {inputs.map((obs) => (
                  <li key={obs.observation_id}>
                    <span className="mono">{obs.command_text || obs.summary}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* The AI's structured decision (output). */}
      <div className="io ai">
        <span className="io-label">AI DECISION</span>
        <div className="io-body">
          {isStop ? (
            <>
              <div className="io-line">
                <span className="muted">Summary:</span> {stop?.summary ?? '—'}
              </div>
              <div className="io-line">
                <span className="muted">Hypothesis:</span> {stop?.hypothesis ?? '—'}
              </div>
              <div className="io-line">
                <span className="muted">Cited evidence:</span>{' '}
                <span className="mono">{(stop?.evidence_observation_ids ?? []).join(', ') || '—'}</span>
              </div>
            </>
          ) : (
            <>
              <div className="io-line">
                <span className="muted">Hypothesis:</span> {command?.hypothesis_reference ?? '—'}
              </div>
              <div className="io-line">
                <span className="muted">Intent:</span> {command?.expected_intent ?? '—'}
              </div>
              <div className="io-line">
                <span className="muted">Command (verbatim, unchanged by the controller):</span>
                <pre className="codeblock">{command?.command_text ?? '—'}</pre>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Deterministic sandbox result the model then observed. */}
      {observation && (
        <div className="io result">
          <span className="io-label">SANDBOX RESULT</span>
          <div className="io-body">
            <div className="io-line">
              <span className="muted">Exit code:</span>{' '}
              <span className="mono">{String(facts.exit_code ?? '—')}</span>
              {factKeys.includes('http_status_codes') && (
                <>
                  {'  '}
                  <span className="muted">HTTP:</span>{' '}
                  <span className="mono">{JSON.stringify(facts.http_status_codes)}</span>
                </>
              )}
            </div>
            <div className="io-line">
              <span className="muted">Normalized facts:</span>
              <pre className="codeblock">{JSON.stringify(facts, null, 2)}</pre>
            </div>
            {observation.stdout && (
              <div className="io-line">
                <span className="muted">stdout:</span>
                <pre className="codeblock">{clip(observation.stdout)}</pre>
              </div>
            )}
            {observation.stderr && (
              <div className="io-line">
                <span className="muted">stderr:</span>
                <pre className="codeblock">{clip(observation.stderr)}</pre>
              </div>
            )}
          </div>
        </div>
      )}

      <details className="turn-raw">
        <summary>Raw turn JSON (model call · command · observation)</summary>
        <pre className="codeblock">
          {JSON.stringify({ model_call: call, command, observation }, null, 2)}
        </pre>
      </details>
    </div>
  )
}

export function BeastConsole({
  embedded = false,
  initialTargetRef,
  initialScenario,
  operatorProfileId,
  onBack,
}: {
  embedded?: boolean
  initialTargetRef?: string
  initialScenario?: string
  operatorProfileId?: string
  onBack?: () => void
}) {
  const [config, setConfig] = useState<BeastConfig>()
  const [loading, setLoading] = useState(true)
  const [preflight, setPreflight] = useState<BeastPreflight>()
  const [targetRef, setTargetRef] = useState<string | undefined>(initialTargetRef)
  const [operatorId, setOperatorId] = useState('')
  const [scenario, setScenario] = useState<string>()
  const [requestBudget, setRequestBudget] = useState('')
  const [durationMinutes, setDurationMinutes] = useState('')
  const [phrase, setPhrase] = useState('')
  const [run, setRun] = useState<BeastRunView>()
  const [events, setEvents] = useState<BeastEvent[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const [notice, setNotice] = useState<string>()
  const pollRef = useRef<number | undefined>(undefined)

  useEffect(() => {
    consoleApi
      .beastConfig()
      .then((cfg) => setConfig(cfg))
      .catch((e) => setError(e instanceof Error ? e.message : 'Could not load toolbox config.'))
      .finally(() => setLoading(false))
    return () => {
      if (pollRef.current !== undefined) window.clearInterval(pollRef.current)
    }
  }, [])

  const requiredPhrase = preflight ? `ASSESS ${preflight.target.name}` : ''
  const phraseOk = phrase.trim() === requiredPhrase && requiredPhrase !== ''
  const operatorOk = /^[A-Za-z0-9._@-]{3,80}$/.test(operatorId)
  const requestBudgetValue = Number(requestBudget)
  const durationSeconds = Math.round(Number(durationMinutes) * 60)
  const resourceLimitsOk = Boolean(
    preflight &&
    Number.isInteger(requestBudgetValue) &&
    requestBudgetValue >= 1 &&
    requestBudgetValue <= preflight.resources.max_target_connections &&
    Number.isFinite(durationSeconds) &&
    durationSeconds >= 10 &&
    durationSeconds <= preflight.resources.total_wall_time_seconds,
  )
  const canActivate = Boolean(
    preflight && scenario && phraseOk && operatorOk && resourceLimitsOk && !busy,
  )

  const selectTarget = useCallback(async (ref: string) => {
    setTargetRef(ref)
    setPreflight(undefined)
    setScenario(undefined)
    setPhrase('')
    setError(undefined)
    setBusy(true)
    try {
      const pf = await consoleApi.beastPreflight(ref)
      setPreflight(pf)
      setRequestBudget(String(pf.resources.max_target_connections))
      setDurationMinutes(String(pf.resources.total_wall_time_seconds / 60))
      if (initialScenario && pf.enabled_capabilities.includes(initialScenario)) {
        setScenario(initialScenario)
      } else if (pf.enabled_capabilities.length === 1) {
        setScenario(pf.enabled_capabilities[0])
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Preflight was rejected by the controller.')
    } finally {
      setBusy(false)
    }
  }, [initialScenario])

  useEffect(() => {
    if (initialTargetRef) void selectTarget(initialTargetRef)
  }, [initialTargetRef, selectTarget])

  const poll = useCallback((runId: string) => {
    if (pollRef.current !== undefined) window.clearInterval(pollRef.current)
    const load = () =>
      consoleApi
        .beastRun(runId)
        .then((detail) => {
          setRun(detail.run)
          setEvents(detail.events)
          if (TERMINAL_STATES.has(detail.run.state) && pollRef.current !== undefined) {
            window.clearInterval(pollRef.current)
            pollRef.current = undefined
          }
        })
        .catch(() => undefined)
    void load()
    pollRef.current = window.setInterval(load, 2000)
  }, [])

  const activate = useCallback(async () => {
    if (!config || !preflight || !targetRef || !scenario) return
    setBusy(true)
    setError(undefined)
    try {
      const lease = await consoleApi.beastIssueLease({
        operator_id: operatorId,
        actor_type: 'OPERATOR',
        target_ref: targetRef,
        profile_id: config.profile_id,
        ...(operatorProfileId ? { operator_profile_id: operatorProfileId } : {}),
        confirmation: phrase.trim(),
        requested_resources: {
          ...preflight.resources,
          max_target_connections: requestBudgetValue,
          total_wall_time_seconds: durationSeconds,
        },
      })
      const created = await consoleApi.beastCreateRun({
        lease_id: lease.lease_id,
        scenario_id: scenario,
      })
      setRun(created)
      setEvents([])
      setNotice(`Lease ${lease.lease_id} issued; run ${created.run_id} started.`)
      poll(created.run_id)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The toolbox assessment was rejected by the controller.')
    } finally {
      setBusy(false)
    }
  }, [
    config,
    preflight,
    targetRef,
    scenario,
    operatorId,
    operatorProfileId,
    phrase,
    requestBudgetValue,
    durationSeconds,
    poll,
  ])

  const stop = useCallback(async () => {
    if (!run) return
    setBusy(true)
    try {
      const stopped = await consoleApi.beastStop(run.run_id, operatorId)
      setRun(stopped)
      setNotice('Emergency stop sent: lease revoked, sandbox destroyed, target blocked for review.')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Emergency stop failed.')
    } finally {
      setBusy(false)
    }
  }, [run, operatorId])

  const reset = () => {
    if (pollRef.current !== undefined) window.clearInterval(pollRef.current)
    pollRef.current = undefined
    setRun(undefined)
    setEvents([])
    setPreflight(undefined)
    setTargetRef(initialTargetRef)
    setScenario(undefined)
    setRequestBudget('')
    setDurationMinutes('')
    setPhrase('')
    setNotice(undefined)
    setError(undefined)
  }

  const running = run && !TERMINAL_STATES.has(run.state)
  const verifier = run?.verifier_conclusion
  const verifierStatus = verifier ? String(verifier.status ?? '') : ''
  const turns = useMemo(() => (run ? buildTurns(run, events) : []), [run, events])
  const targetLine = preflight ? `${preflight.target.origin}${preflight.target.base_path}` : ''
  const objectiveLabel = run ? SCENARIO_LABELS[run.scenario_id] ?? run.scenario_id : ''

  const resourceItems = useMemo<[string, string][]>(() => {
    if (!preflight) return []
    const r = preflight.resources
    return [
      ['Max commands', String(r.max_commands)],
      ['Wall time', `${r.total_wall_time_seconds}s`],
      ['Per-command timeout', `${r.per_command_timeout_seconds}s`],
      ['Max request rate', `${r.max_request_rate_per_second}/s`],
      ['Max connections', String(r.max_target_connections)],
      ['Lease expiry', `${preflight.automatic_expiry_seconds}s`],
    ]
  }, [preflight])

  if (loading) return <Loading label="Loading assessment toolbox…" />

  return (
    <div className="stack">
      <div className="page-head">
        {embedded ? <h2>Autonomous toolbox assessment</h2> : <h1>Autonomous toolbox assessment</h1>}
        <p>
          The model can select from the verified tool inventory inside a disposable, network-isolated
          workspace. The independent verifier alone confirms findings.
        </p>
        {onBack && <button className="btn ghost" onClick={onBack}>← Back to assessments</button>}
      </div>

      {!embedded && config?.tools?.length ? (
        <div className="panel toolbox-panel">
          <div className="panel-head">
            <div>
              <h2>Installed sandbox toolbox</h2>
              <span className="sub">Controller-reported inventory · {config.tools.length} tools</span>
            </div>
          </div>
          <div className="toolbox-grid">
            {config.tools.map((tool) => (
              <div className="toolbox-item" key={tool.name}>
                <div>
                  <strong className="mono">{tool.name}</strong>
                  <Pill tone="neutral">{tool.category}</Pill>
                </div>
                <p>{tool.purpose}</p>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {!config?.enabled ? (
        <div className="banner critical">
          <div className="banner-body">
            <strong>The disposable toolbox is unavailable.</strong> Start the stack with the
            toolbox enabled so the controller, sandbox supervisor and gateway are all ready. It
            cannot be enabled from the browser.
          </div>
        </div>
      ) : (
        <>
          <div className="banner">
            <div className="banner-body">
              <strong>{config.technical_subtitle}.</strong> {config.boundary_description} Activation
              is operator-only and requires a typed confirmation phrase and a server preflight.
            </div>
          </div>

          {error && (
            <div className="banner critical">
              <div className="banner-body">
                <strong>Rejected.</strong> {error}
              </div>
            </div>
          )}
          {notice && (
            <div className="banner">
              <div className="banner-body">{notice}</div>
            </div>
          )}

          {!run && (
            <>
              {!initialTargetRef && <div className="panel">
                <div className="panel-head">
                  <h2>1 · Select a synthetic target</h2>
                  <Pill tone="neutral">{config.mode}</Pill>
                </div>
                <div className="option-list">
                  {config.target_refs.map((ref) => (
                    <button
                      key={ref}
                      className={`option ${targetRef === ref ? 'selected' : ''}`}
                      aria-pressed={targetRef === ref}
                      disabled={busy}
                      onClick={() => void selectTarget(ref)}
                    >
                      <strong className="mono">{ref}</strong>
                    </button>
                  ))}
                </div>
              </div>}

              {preflight && (
                <div className="panel">
                  <div className="panel-head">
                    <h2>Review controls &amp; confirm</h2>
                    <Pill tone="neutral">{preflight.target.environment}</Pill>
                  </div>
                  <Kv
                    items={[
                      ['Target', preflight.target.name],
                      ['Origin', <span className="mono" key="o">{preflight.target.origin}</span>],
                      ['Authorized path', <span className="mono" key="p">{preflight.target.allowed_path_prefix}</span>],
                      ['Allowed methods', preflight.target.allowed_methods.join(', ')],
                      ['Engines', preflight.enabled_engines.join(', ')],
                      ...resourceItems.map(([k, v]) => [k, v] as [string, string]),
                      ['Emergency stop', preflight.emergency_stop],
                    ]}
                  />

                  <div className="filters" style={{ marginTop: 16 }}>
                    <label className="field">
                      <span>Operator ID</span>
                      <input
                        value={operatorId}
                        onChange={(e) => setOperatorId(e.target.value)}
                        placeholder="e.g. operator-1"
                        aria-invalid={operatorId !== '' && !operatorOk}
                      />
                    </label>
                    <label className="field">
                      <span>Scenario</span>
                      {operatorProfileId ? (
                        <>
                          <input
                            value={SCENARIO_LABELS[scenario ?? ''] ?? scenario ?? ''}
                            disabled
                            aria-label="Scenario (bound to the selected assessment profile)"
                          />
                          <small className="muted">
                            Bound to the selected assessment profile — the controller rejects any
                            other scenario.
                          </small>
                        </>
                      ) : (
                        <select value={scenario ?? ''} onChange={(e) => setScenario(e.target.value || undefined)}>
                          <option value="">Select a scenario…</option>
                          {preflight.enabled_capabilities.map((cap) => (
                            <option key={cap} value={cap}>
                              {SCENARIO_LABELS[cap] ?? cap}
                            </option>
                          ))}
                        </select>
                      )}
                    </label>
                    <label className="field">
                      <span>Target connection budget</span>
                      <input
                        type="number"
                        min={1}
                        max={preflight.resources.max_target_connections}
                        step={1}
                        value={requestBudget}
                        onChange={(e) => setRequestBudget(e.target.value)}
                      />
                      <small className="muted">
                        Maximum {preflight.resources.max_target_connections}
                      </small>
                    </label>
                    <label className="field">
                      <span>Maximum duration (minutes)</span>
                      <input
                        type="number"
                        min={10 / 60}
                        max={preflight.resources.total_wall_time_seconds / 60}
                        step={0.1}
                        value={durationMinutes}
                        onChange={(e) => setDurationMinutes(e.target.value)}
                      />
                      <small className="muted">
                        Maximum {preflight.resources.total_wall_time_seconds / 60} minutes
                      </small>
                    </label>
                  </div>

                  <label className="field" style={{ marginTop: 12 }}>
                    <span>
                      Type the exact confirmation phrase to activate:{' '}
                      <code className="mono">{requiredPhrase}</code>
                    </span>
                    <input
                      value={phrase}
                      onChange={(e) => setPhrase(e.target.value)}
                      placeholder="Type the phrase exactly"
                      aria-invalid={phrase !== '' && !phraseOk}
                      autoComplete="off"
                    />
                  </label>

                  <div className="modal-actions" style={{ marginTop: 16 }}>
                    <button className="btn ghost" onClick={onBack ?? reset} disabled={busy}>
                      Back
                    </button>
                    <button className="btn danger" onClick={() => void activate()} disabled={!canActivate}>
                      {busy ? 'Starting…' : 'Start toolbox assessment'}
                    </button>
                  </div>
                </div>
              )}
            </>
          )}

          {run && (
            <div className="panel">
              <div className="panel-head">
                <h2>Toolbox assessment run</h2>
                <Pill tone={stateTone(run.state)} running={running}>
                  {run.state}
                </Pill>
              </div>
              <Kv
                items={[
                  ['Run ID', <span className="mono" key="r">{run.run_id}</span>],
                  ['Scenario', SCENARIO_LABELS[run.scenario_id] ?? run.scenario_id],
                  ['Model', <span className="mono" key="m">{run.model}</span>],
                  ['Commands', String(run.commands.length)],
                  ['Model calls', String(run.model_calls.length)],
                  ['Cleanup verified', run.cleanup_verified ? 'Yes' : 'No'],
                  ['Workspace destroyed', run.workspace_destroyed ? 'Yes' : 'No'],
                  ...(run.stop_reason ? [['Outcome', run.stop_reason] as [string, string]] : []),
                  ...(verifierStatus
                    ? [['Verifier', <Pill tone={verifierTone(verifierStatus)} key="v">{verifierStatus}</Pill>] as [string, ReactNode]]
                    : []),
                ]}
              />

              <div className="modal-actions" style={{ marginTop: 12 }}>
                {running ? (
                  <button className="btn danger" onClick={() => void stop()} disabled={busy || !operatorOk}>
                    ⏹ Emergency stop
                  </button>
                ) : (
                  <button className="btn ghost" onClick={reset}>
                    Start another assessment
                  </button>
                )}
              </div>

              <div className="panel-head" style={{ marginTop: 20 }}>
                <h3>Model transcript</h3>
                <span className="sub">input → AI decision → sandbox result · {turns.length} turn(s)</span>
              </div>
              {turns.length === 0 ? (
                <p className="muted">
                  {running ? 'Waiting for the model’s first decision…' : 'No model turns were recorded.'}
                </p>
              ) : (
                <div className="transcript">
                  {turns.map((turn) => (
                    <TranscriptTurn
                      key={turn.call.sequence}
                      turn={turn}
                      objectiveLabel={objectiveLabel}
                      targetLine={targetLine}
                    />
                  ))}
                </div>
              )}

              <div className="panel-head" style={{ marginTop: 20 }}>
                <h3>Audit events</h3>
                <span className="sub">{events.length} event(s)</span>
              </div>
              <div className="panel">
                {events.length === 0 ? (
                  <p className="muted">No events yet.</p>
                ) : (
                  events.map((event) => (
                    <div className="activity-item" key={event.event_id}>
                      <time>{event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '—'}</time>
                      <Pill tone={event.actor_type === 'VERIFIER' ? 'success' : 'neutral'}>
                        {event.actor_type.replaceAll('_', ' ')}
                      </Pill>
                      <span className="summary">{event.event_type.replaceAll('_', ' ')}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
