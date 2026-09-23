import { useMemo, useState } from 'react'
import type { AssessmentProfile, ProfileCapability, Run, TargetEntry } from './api'
import { Pill } from './components'

type Props = {
  targets: TargetEntry[]
  profiles: AssessmentProfile[]
  onStart: (target: TargetEntry, profile: AssessmentProfile) => Promise<Run>
  onStarted: (run: Run) => void
  onCancel: () => void
}

const STEPS = ['Target', 'Assessment', 'Controls', 'Review & Start']

function timeout(ms: number): string {
  if (!ms) return '—'
  return ms >= 60_000 ? `${Math.round(ms / 60_000)} min` : `${Math.round(ms / 1000)} s`
}

function primaryCapability(profile: AssessmentProfile): ProfileCapability | undefined {
  return profile.capabilities[0]
}

export function NewAssessment({ targets, profiles, onStart, onStarted, onCancel }: Props) {
  const [step, setStep] = useState(0)
  const [targetRef, setTargetRef] = useState<string | undefined>(
    targets.length === 1 ? targets[0]?.target_ref : undefined,
  )
  const [profileId, setProfileId] = useState<string>()
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string>()

  const target = useMemo(() => targets.find((t) => t.target_ref === targetRef), [targets, targetRef])
  const profile = useMemo(() => profiles.find((p) => p.profile_id === profileId), [profiles, profileId])

  // Only profiles the selected target supports AND the backend can execute are startable.
  const targetProfiles = useMemo(() => {
    if (!target) return []
    return profiles.filter((p) => target.supported_profile_ids.includes(p.profile_id))
  }, [profiles, target])

  const cap = profile ? primaryCapability(profile) : undefined
  const canStart = Boolean(target && profile && profile.available && !starting)

  const start = async () => {
    if (!target || !profile || starting) return
    setStarting(true)
    setError(undefined)
    try {
      const run = await onStart(target, profile)
      onStarted(run)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The controller rejected the assessment.')
      setStarting(false)
    }
  }

  const next = () => setStep((s) => Math.min(STEPS.length - 1, s + 1))
  const back = () => setStep((s) => Math.max(0, s - 1))

  return (
    <div>
      <div className="page-head">
        <h1>New assessment</h1>
        <p>Select an authorized target and an assessment profile, review the controls, then start.</p>
      </div>

      <div className="stepper">
        {STEPS.map((label, index) => (
          <div className={`step ${index === step ? 'active' : index < step ? 'done' : ''}`} key={label}>
            <i>{index < step ? '✓' : index + 1}</i>
            {label}
          </div>
        ))}
      </div>

      {step === 0 && (
        <div className="panel">
          <div className="panel-head">
            <h2>Choose an authorized target</h2>
            <span className="sub">From controller-authorized inventory only</span>
          </div>
          <div className="option-list">
            {targets.map((entry) => (
              <button
                type="button"
                key={entry.target_ref}
                className={`option ${targetRef === entry.target_ref ? 'selected' : ''}`}
                onClick={() => {
                  setTargetRef(entry.target_ref)
                  setProfileId(undefined)
                }}
                aria-pressed={targetRef === entry.target_ref}
              >
                <span className="opt-radio" />
                <span className="opt-body">
                  <span className="opt-title">
                    {entry.name}
                    <Pill tone="neutral">{entry.type}</Pill>
                  </span>
                  <span className="opt-desc">{entry.description}</span>
                  <span className="opt-meta">
                    <span className="mono">{entry.target_ref}</span>
                    <span>· {entry.environment}</span>
                  </span>
                </span>
              </button>
            ))}
          </div>
          <div className="wizard-actions">
            <button className="btn ghost" onClick={onCancel}>
              Cancel
            </button>
            <button className="btn primary" disabled={!target} onClick={next}>
              Continue
            </button>
          </div>
        </div>
      )}

      {step === 1 && target && (
        <div className="panel">
          <div className="panel-head">
            <h2>Choose an assessment</h2>
            <span className="sub">Target: {target.name}</span>
          </div>
          {targetProfiles.length === 0 && (
            <p className="muted">No assessment profiles are registered for this target.</p>
          )}
          <div className="option-list">
            {targetProfiles.map((entry) => {
              const disabled = !entry.available
              return (
                <button
                  type="button"
                  key={entry.profile_id}
                  className={`option ${profileId === entry.profile_id ? 'selected' : ''} ${disabled ? 'disabled' : ''}`}
                  onClick={() => !disabled && setProfileId(entry.profile_id)}
                  aria-disabled={disabled}
                  aria-pressed={profileId === entry.profile_id}
                >
                  <span className="opt-radio" />
                  <span className="opt-body">
                    <span className="opt-title">
                      {entry.display_name}
                      {entry.advanced && <Pill tone="neutral">Advanced</Pill>}
                      {disabled ? <Pill tone="warning">Unavailable</Pill> : <Pill tone="success">Available</Pill>}
                    </span>
                    <span className="opt-desc">{entry.operator_summary}</span>
                    {disabled && (
                      <span className="opt-meta" style={{ color: 'var(--warning)' }}>
                        {entry.unavailable_reason}
                      </span>
                    )}
                    <details className="disclosure" onClick={(e) => e.stopPropagation()}>
                      <summary>How this assessment runs</summary>
                      <div className="disclosure-body">
                        {entry.how_it_runs}
                        <div className="opt-meta" style={{ marginTop: 8 }}>
                          <span>Engine: {entry.engine}</span>
                          {entry.capabilities.map((c) => (
                            <span key={c.capability_id}>· {c.title}</span>
                          ))}
                        </div>
                      </div>
                    </details>
                  </span>
                </button>
              )
            })}
          </div>
          <div className="wizard-actions">
            <button className="btn ghost" onClick={back}>
              Back
            </button>
            <button className="btn primary" disabled={!profile || !profile.available} onClick={next}>
              Continue
            </button>
          </div>
        </div>
      )}

      {step === 2 && profile && (
        <div className="panel">
          <div className="panel-head">
            <h2>Execution controls</h2>
            <span className="sub">Safe defaults from controller policy</span>
          </div>
          <p className="muted" style={{ marginTop: -6 }}>
            These limits come from the controller's capability policy and are enforced regardless of
            the browser.
          </p>
          <dl className="kv wide" style={{ marginTop: 12 }}>
            <div style={{ display: 'contents' }}>
              <dt>Authorization lease</dt>
              <dd>Synthetic-lab scope · single bounded run</dd>
            </div>
            <div style={{ display: 'contents' }}>
              <dt>Target request budget</dt>
              <dd>{cap ? `${cap.request_budget} request(s)` : '—'}</dd>
            </div>
            <div style={{ display: 'contents' }}>
              <dt>Execution timeout</dt>
              <dd>{cap ? timeout(cap.time_budget_ms) : '—'}</dd>
            </div>
            <div style={{ display: 'contents' }}>
              <dt>Concurrency</dt>
              <dd>{cap ? `${cap.concurrency_budget}` : '—'}</dd>
            </div>
            <div style={{ display: 'contents' }}>
              <dt>Credential reference</dt>
              <dd>{cap?.requires_authentication ? 'Synthetic credential profiles (opaque reference)' : 'None required'}</dd>
            </div>
            <div style={{ display: 'contents' }}>
              <dt>Capability scope</dt>
              <dd>{profile.capabilities.map((c) => c.capability_id).join(', ')}</dd>
            </div>
            <div style={{ display: 'contents' }}>
              <dt>Cleanup policy</dt>
              <dd>In-process execution — no disposable containers or networks are created.</dd>
            </div>
          </dl>
          <div className="wizard-actions">
            <button className="btn ghost" onClick={back}>
              Back
            </button>
            <button className="btn primary" onClick={next}>
              Continue
            </button>
          </div>
        </div>
      )}

      {step === 3 && target && profile && (
        <div className="panel">
          <div className="panel-head">
            <h2>Review and start</h2>
            <span className="sub">Confirm before execution</span>
          </div>
          <div className="review-grid">
            <div>
              <dl className="kv">
                <div style={{ display: 'contents' }}>
                  <dt>Target</dt>
                  <dd>
                    {target.name} <span className="mono muted">({target.target_ref})</span>
                  </dd>
                </div>
                <div style={{ display: 'contents' }}>
                  <dt>Assessment</dt>
                  <dd>{profile.display_name}</dd>
                </div>
                <div style={{ display: 'contents' }}>
                  <dt>Engine</dt>
                  <dd>{profile.engine}</dd>
                </div>
                <div style={{ display: 'contents' }}>
                  <dt>Authorization</dt>
                  <dd>Synthetic-lab scope · single bounded run</dd>
                </div>
                <div style={{ display: 'contents' }}>
                  <dt>Budget / timeout</dt>
                  <dd>
                    {cap ? `${cap.request_budget} request(s)` : '—'} · {cap ? timeout(cap.time_budget_ms) : '—'}
                  </dd>
                </div>
                <div style={{ display: 'contents' }}>
                  <dt>Credentials</dt>
                  <dd>{cap?.requires_authentication ? 'Synthetic reference only' : 'None referenced'}</dd>
                </div>
              </dl>
            </div>
            <div>
              <p className="muted" style={{ margin: '0 0 6px' }}>This assessment is allowed to</p>
              <ul className="allow-list">
                <li>Send controller-compiled read-only requests within the request budget</li>
                <li>Produce hypotheses and evidence for the independent verifier</li>
              </ul>
              <p className="muted" style={{ margin: '14px 0 6px' }}>It is not allowed to</p>
              <ul className="deny-list">
                <li>Send state-changing requests or write to the target</li>
                <li>Reach any origin outside the authorized target</li>
                <li>Confirm its own findings — only the Aegis verifier can</li>
              </ul>
            </div>
          </div>
          {error && (
            <div className="banner critical" style={{ marginTop: 16 }}>
              <div className="banner-body">
                <strong>The assessment could not be started</strong>
                {error}
              </div>
            </div>
          )}
          <div className="wizard-actions">
            <button className="btn ghost" onClick={back} disabled={starting}>
              Back
            </button>
            <button className="btn primary lg" disabled={!canStart} onClick={start}>
              {starting ? 'Starting…' : 'Start assessment'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
