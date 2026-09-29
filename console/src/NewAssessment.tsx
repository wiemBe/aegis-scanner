import { useCallback, useEffect, useMemo, useState } from 'react'
import type { AssessmentProfile, ProfileCapability, TargetEntry, ToolboxHealth } from './api'
import { AddTarget } from './AddTarget'
import { consoleApi } from './api'
import { BeastConsole } from './Beast'
import { Empty, Pill } from './components'
import type { Tone } from './format'
import { StandardCampaign } from './StandardCampaign'
import { ToolboxCampaign } from './ToolboxCampaign'

type Props = {
  targets: TargetEntry[]
  profiles: AssessmentProfile[]
  onStart: (
    target: TargetEntry,
    profile: AssessmentProfile,
    limits: { request_budget: number; max_duration_minutes: number },
  ) => Promise<{ run_id: string }>
  onStarted: (runId: string) => void
  onTargetCreated: (created: TargetEntry) => void
  onCancel: () => void
}

function isProduction(target: TargetEntry): boolean {
  return !target.synthetic && target.environment.toUpperCase().includes('PRODUCTION')
}

// The environment word shown on a target card. Catalog targets carry controller enums
// (SYNTHETIC_LAB, SYNTHETIC_RANGE, PRODUCTION…) and operator-onboarded targets carry the tier
// they were saved with; both collapse to one short word plus the pill tone.
function environmentView(target: TargetEntry): { label: string; tone: Tone } {
  if (target.synthetic) {
    const environment = target.environment.toUpperCase()
    if (environment.includes('RANGE')) return { label: 'Synthetic range', tone: 'neutral' }
    if (environment.includes('LAB')) return { label: 'Synthetic lab', tone: 'neutral' }
    return { label: 'Synthetic', tone: 'neutral' }
  }
  return isProduction(target)
    ? { label: 'Production', tone: 'warning' }
    : { label: 'Company', tone: 'success' }
}

// The endpoint as an operator reads it: no scheme, and no controller annotation such as
// "(synthetic range)" — the environment pill already states where the target lives.
function endpointLabel(target: TargetEntry): string {
  const scope = target.authorized_scope[0] ?? target.target_ref
  return scope.replace(/\s*\([^)]*\)\s*$/, '').trim().replace(/^https?:\/\//, '')
}

// Two-letter monogram, so a card is recognizable at a glance when the names run together.
function monogram(name: string): string {
  const initials = name
    .split(/[\s(]+/)
    .map((word) => word.replace(/[^A-Za-z0-9]/g, '').charAt(0))
    .filter(Boolean)
    .join('')
    .toUpperCase()
  return initials.slice(0, 2) || name.slice(0, 2).toUpperCase()
}

// A scanner-style flow: scope first, then a template gallery, then one configuration workspace.
// Profiles remain controller-owned; the UI only presents them with familiar scan-template labels.
const STEPS = ['Target', 'Scan template', 'Configure & launch']
const ALL_PROFILES_ID = '__ALL_COMPATIBLE_PROFILES__'
const TOOLBOX_SCENARIOS: Record<string, string> = {
  OUTSIDE_IN_WEB_DISCOVERY_V1: 'endpoint_discovery',
  TOOLBOX_INFORMATION_EXPOSURE_V1: 'information_exposure',
  TOOLBOX_BOLA_READONLY_V1: 'bola_readonly',
  SQLMAP_AUTHORIZED_WEB_V1: 'safe_injection',
}

function primaryCapability(profile: AssessmentProfile): ProfileCapability | undefined {
  return profile.capabilities[0]
}

function plural(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`
}

// Human labels for the tooling each profile executes. TOOLBOX/RECON profiles name their tools
// explicitly in ``tools``; engine-backed profiles execute in (or through) their named engine, so
// the engine label stands in for the tool the operator sees called.
const ENGINE_TOOL_LABELS: Record<string, string> = {
  AEGIS_NATIVE: 'Aegis native engine (in-process)',
  NUCLEI: 'Nuclei (isolated runner)',
  ZAP: 'OWASP ZAP (isolated runner)',
  TOOLBOX: 'Disposable toolbox',
  RECON_NMAP: 'Nmap (network runner)',
}

function toolLabels(profile: AssessmentProfile): string[] {
  if (profile.tools?.length) return profile.tools
  return [ENGINE_TOOL_LABELS[profile.engine] ?? profile.engine]
}

// Impact facts derived from the capability policy — the same data the controller enforces.
function isStateChanging(profile: AssessmentProfile): boolean {
  return profile.capabilities.some((c) => c.state_changing_possible)
}

function isActiveProbing(profile: AssessmentProfile): boolean {
  return profile.capabilities.some((c) => c.activity === 'ACTIVE')
}

function usesCredentials(profile: AssessmentProfile): boolean {
  return profile.capabilities.some((c) => c.requires_authentication)
}

function maxRequestBudget(profile: AssessmentProfile): number {
  return profile.capabilities.reduce((max, c) => Math.max(max, c.request_budget), 0)
}

function maxTimeMinutes(profile: AssessmentProfile): number {
  return profile.capabilities.reduce((max, c) => Math.max(max, c.time_budget_ms), 0) / 60_000
}

function maxConcurrency(profile: AssessmentProfile): number {
  return profile.capabilities.reduce((max, c) => Math.max(max, c.concurrency_budget), 0)
}

type TemplateCategory = 'Discovery' | 'Vulnerabilities' | 'Web applications'
type ConfigTab = 'settings' | 'credentials' | 'checks' | 'advanced'

function templateCategory(profile: AssessmentProfile): TemplateCategory {
  if (profile.engine === 'RECON_NMAP' || profile.profile_id === 'OUTSIDE_IN_WEB_DISCOVERY_V1') return 'Discovery'
  if (profile.engine === 'NUCLEI' || profile.profile_id === 'TOOLBOX_INFORMATION_EXPOSURE_V1') return 'Vulnerabilities'
  return 'Web applications'
}

function templateLabel(profile: AssessmentProfile): string {
  if (profile.advanced) return 'Advanced scan'
  if (profile.engine === 'ZAP') return 'Passive scan'
  return 'Basic scan'
}

const CATEGORY_MARKS: Record<TemplateCategory, string> = {
  Discovery: '⌖',
  Vulnerabilities: '◇',
  'Web applications': '</>',
}

export function NewAssessment({
  targets,
  profiles,
  onStart,
  onStarted,
  onTargetCreated,
  onCancel,
}: Props) {
  const [step, setStep] = useState(0)
  const [targetRef, setTargetRef] = useState<string | undefined>(
    targets.length === 1 ? targets[0]?.target_ref : undefined,
  )
  const [profileId, setProfileId] = useState<string>()
  const [requestBudget, setRequestBudget] = useState('')
  const [durationMinutes, setDurationMinutes] = useState('')
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string>()
  const [adding, setAdding] = useState(false)
  const [toolboxHealth, setToolboxHealth] = useState<ToolboxHealth>()
  const [toolboxLoading, setToolboxLoading] = useState(true)
  const [toolboxError, setToolboxError] = useState<string>()
  const [configTab, setConfigTab] = useState<ConfigTab>('settings')

  const selectable = useMemo(() => targets.filter((t) => t.enabled), [targets])
  const target = useMemo(() => targets.find((t) => t.target_ref === targetRef), [targets, targetRef])
  const profile = useMemo(() => profiles.find((p) => p.profile_id === profileId), [profiles, profileId])
  const allProfilesMode = profileId === ALL_PROFILES_ID

  // Only profiles the selected target supports are offered; availability still gates selection.
  const targetProfiles = useMemo(() => {
    if (!target) return []
    return profiles.filter((p) => target.supported_profile_ids.includes(p.profile_id))
  }, [profiles, target])
  const allToolboxProfiles = targetProfiles.length > 1 && targetProfiles.every((entry) => entry.engine === 'TOOLBOX')
  const canRunAll = targetProfiles.length > 1 && targetProfiles.every(
    (entry) => entry.available && (
      entry.engine !== 'TOOLBOX' || Boolean(TOOLBOX_SCENARIOS[entry.profile_id])
    ),
  )

  const loadToolboxHealth = useCallback(async () => {
    setToolboxLoading(true)
    setToolboxError(undefined)
    try {
      setToolboxHealth(await consoleApi.toolboxHealth())
    } catch (reason) {
      setToolboxError(reason instanceof Error ? reason.message : 'Tool checks could not be loaded.')
    } finally {
      setToolboxLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadToolboxHealth()
  }, [loadToolboxHealth])

  const cap = profile ? primaryCapability(profile) : undefined
  const requestBudgetValue = Number(requestBudget)
  const durationMinutesValue = Number(durationMinutes)
  const limitsValid = Boolean(
    cap &&
    Number.isInteger(requestBudgetValue) &&
    requestBudgetValue >= 1 &&
    requestBudgetValue <= cap.request_budget &&
    Number.isFinite(durationMinutesValue) &&
    durationMinutesValue > 0 &&
    durationMinutesValue * 60_000 <= cap.time_budget_ms,
  )
  const canStart = Boolean(target && profile && profile.available && limitsValid && !starting)

  const selectTarget = (ref: string) => {
    setTargetRef(ref)
    setProfileId(undefined)
    setRequestBudget('')
    setDurationMinutes('')
  }

  const selectProfile = (entry: AssessmentProfile) => {
    if (!entry.available) return
    setProfileId(entry.profile_id)
    const selectedCap = primaryCapability(entry)
    setRequestBudget(selectedCap ? String(selectedCap.request_budget) : '')
    setDurationMinutes(selectedCap ? String(selectedCap.time_budget_ms / 60_000) : '')
  }

  const selectAllProfiles = () => {
    if (!canRunAll) return
    setProfileId(ALL_PROFILES_ID)
    setRequestBudget('')
    setDurationMinutes('')
  }

  const start = async () => {
    if (!target || !profile || starting) return
    setStarting(true)
    setError(undefined)
    try {
      const { run_id } = await onStart(target, profile, {
        request_budget: requestBudgetValue,
        max_duration_minutes: durationMinutesValue,
      })
      onStarted(run_id)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The controller rejected the assessment.')
      setStarting(false)
    }
  }

  const next = () => setStep((s) => Math.min(STEPS.length - 1, s + 1))
  const back = () => setStep((s) => Math.max(0, s - 1))
  const toolboxState = toolboxHealth?.state ?? 'UNAVAILABLE'

  const toolboxSummary = toolboxHealth?.ready !== undefined && toolboxHealth.total !== undefined
    ? `${toolboxHealth.ready}/${toolboxHealth.total} tools ready`
    : 'Tool readiness unknown'

  const toolboxPanel = (
    <section className="toolbox-compact" aria-labelledby="toolbox-heading">
      <div className="toolbox-compact-head">
        <div>
          <span className="section-kicker">Environment</span>
          <h2 id="toolbox-heading">Assessment toolbox</h2>
        </div>
        <Pill tone={toolboxState === 'READY' ? 'success' : toolboxState === 'DEGRADED' ? 'warning' : 'critical'}>
          {toolboxLoading ? 'Checking…' : toolboxState}
        </Pill>
      </div>
      <p>{toolboxSummary}{toolboxHealth?.reason ? ` · ${toolboxHealth.reason}` : ''}</p>
      {toolboxError && <p className="toolbox-check-error">{toolboxError}</p>}
      <details className="toolbox-details">
        <summary>View tool checks</summary>
        <div className="toolbox-check-grid" aria-label="Assessment toolbox health">
          {(toolboxHealth?.tools ?? []).map((tool) => (
            <div className={`toolbox-check ${tool.status.toLowerCase()}`} key={tool.name} title={tool.purpose}>
              <div>
                <strong className="mono">{tool.name}</strong>
                <Pill tone={tool.status === 'READY' ? 'success' : tool.status === 'UNAVAILABLE' ? 'neutral' : 'critical'}>
                  {tool.status}
                </Pill>
              </div>
              <span>{tool.detail}</span>
            </div>
          ))}
          {!toolboxLoading && !(toolboxHealth?.tools?.length ?? 0) && (
            <span className="muted micro">No tool probe results were returned.</span>
          )}
        </div>
      </details>
      <button className="toolbox-refresh" type="button" disabled={toolboxLoading} onClick={() => void loadToolboxHealth()}>
        Check tools
      </button>
    </section>
  )

  return (
    <div className="assessment-page">
      <header className="assessment-header">
        <div>
          <span className="section-kicker">Controlled execution</span>
          <h1>New assessment</h1>
          <p>Choose what to assess, confirm its impact, then set the run limits.</p>
        </div>
        <button className="btn ghost" type="button" onClick={onCancel}>Close</button>
      </header>

      <nav className="assessment-progress" aria-label="Assessment setup progress">
        {STEPS.map((label, index) => (
          <div className={`progress-step ${index === step ? 'active' : index < step ? 'done' : ''}`} key={label}>
            <span>{index < step ? '✓' : index + 1}</span>
            <div>
              <small>Step {index + 1}</small>
              <strong>{label}</strong>
            </div>
          </div>
        ))}
      </nav>

      {step === 0 && (
        <div className="target-stage">
          <section className="assessment-section target-stage-panel">
            <div className="assessment-section-head">
              <div>
                <span className="section-kicker">Authorized inventory</span>
                <h2>Choose an authorized target</h2>
                <p>Select the asset this scan configuration will be bound to.</p>
              </div>
              <button type="button" className="btn" onClick={() => setAdding(true)}>+ Add authorized target</button>
            </div>
            {selectable.length === 0 ? (
              <Empty title="No enabled targets" copy="Onboard an authorized company target to start an assessment." />
            ) : (
              <div className="target-choice-grid target-stage-grid">
                {selectable.map((entry) => {
                  const environment = environmentView(entry)
                  return (
                    <button
                      type="button"
                      key={entry.target_ref}
                      className={`target-choice ${targetRef === entry.target_ref ? 'selected' : ''}`}
                      onClick={() => selectTarget(entry.target_ref)}
                      aria-pressed={targetRef === entry.target_ref}
                    >
                      <span className="choice-check" aria-hidden="true">
                        {targetRef === entry.target_ref ? '✓' : ''}
                      </span>
                      <span className="target-choice-icon" aria-hidden="true">{monogram(entry.name)}</span>
                      <span className="target-choice-body">
                        <span className="target-choice-title">
                          <span className="target-choice-name">{entry.name}</span>
                          <Pill tone={environment.tone}>{environment.label}</Pill>
                        </span>
                        <span className="target-choice-endpoint mono" title={endpointLabel(entry)}>
                          {endpointLabel(entry)}
                        </span>
                        <span className="target-choice-facts">
                          {entry.type} · {plural(entry.supported_profile_ids.length, 'scan template')}
                        </span>
                      </span>
                    </button>
                  )
                })}
              </div>
            )}
            <div className="stage-actions">
              <button className="btn ghost" onClick={onCancel}>Cancel</button>
              <button className="btn primary lg" disabled={!target} onClick={next}>
                Choose scan template <span aria-hidden="true">→</span>
              </button>
            </div>
          </section>
          {toolboxPanel}
        </div>
      )}

      {step === 1 && target && (
        <div className="template-stage">
          <div className="template-toolbar">
            <button className="btn ghost" onClick={back}>← Change target</button>
            <div className="template-target">
              <span>Target</span>
              <strong>{target.name}</strong>
              <small className="mono">{target.authorized_scope[0]}</small>
            </div>
          </div>

          <section className="template-browser">
            <div className="template-browser-head">
              <div>
                <span className="section-kicker">Scanner library</span>
                <h2>Scan templates</h2>
                <p>Start with a controller-approved template, then tune its limits and checks.</p>
              </div>
              <span className="template-count">{targetProfiles.length} compatible</span>
            </div>

            {targetProfiles.length === 0 ? (
              <Empty title="No templates for this target" copy="This target has no registered assessment profiles." />
            ) : (
              <>
              {targetProfiles.length > 1 && (
                <div className="template-group complete-template-group">
                  <h3>Complete assessment</h3>
                  <button
                    type="button"
                    className={`scan-template-card complete-template-card ${allProfilesMode ? 'selected' : ''}`}
                    disabled={!canRunAll}
                    onClick={selectAllProfiles}
                    aria-pressed={allProfilesMode}
                  >
                    <span className="template-icon" aria-hidden="true">Σ</span>
                    <span className="template-card-body">
                      <span className="template-card-topline">
                        <span>Multi-scan mode</span>
                        <Pill tone={canRunAll ? 'success' : 'warning'}>{canRunAll ? 'Ready' : 'Unavailable'}</Pill>
                      </span>
                      <strong>Complete Assessment</strong>
                      <span className="template-description">
                        Runs all {targetProfiles.length} compatible templates sequentially with an isolated controller-governed run for each scan.
                      </span>
                      <span className="template-meta">{plural(targetProfiles.length, 'scan')} · sequential · one authorized target</span>
                      {!canRunAll && <span className="profile-unavailable">Every compatible template must be ready.</span>}
                    </span>
                    <span className="template-arrow" aria-hidden="true">→</span>
                  </button>
                </div>
              )}
              {(['Discovery', 'Vulnerabilities', 'Web applications'] as TemplateCategory[]).map((category) => {
                const entries = targetProfiles.filter((entry) => templateCategory(entry) === category)
                if (!entries.length) return null
                return (
                  <div className="template-group" key={category}>
                    <h3>{category}</h3>
                    <div className="template-grid">
                      {entries.map((entry) => {
                        const disabled = !entry.available
                        return (
                          <button
                            type="button"
                            key={entry.profile_id}
                            className={`scan-template-card ${profileId === entry.profile_id ? 'selected' : ''}`}
                            disabled={disabled}
                            onClick={() => selectProfile(entry)}
                            aria-pressed={profileId === entry.profile_id}
                          >
                            <span className="template-icon" aria-hidden="true">{CATEGORY_MARKS[category]}</span>
                            <span className="template-card-body">
                              <span className="template-card-topline">
                                <span>{templateLabel(entry)}</span>
                                {disabled ? <Pill tone="warning">Unavailable</Pill> : <Pill tone="success">Ready</Pill>}
                              </span>
                              <strong>{entry.display_name}</strong>
                              <span className="template-description">{entry.operator_summary}</span>
                              <span className="template-meta">
                                {toolLabels(entry).join(' · ')} · {plural(maxRequestBudget(entry), 'request')} · {maxTimeMinutes(entry)} min
                              </span>
                              {disabled && <span className="profile-unavailable">{entry.unavailable_reason}</span>}
                            </span>
                            <span className="template-arrow" aria-hidden="true">→</span>
                          </button>
                        )
                      })}
                    </div>
                  </div>
                )
              })}
              </>
            )}
          </section>

          <aside className="template-selection-bar">
            <div>
              <span className="section-kicker">Selected template</span>
              <strong>{allProfilesMode ? 'Complete Assessment' : profile?.display_name ?? 'Choose a scan template'}</strong>
              <small>{allProfilesMode ? `${plural(targetProfiles.length, 'scan')} · sequential campaign` : profile ? `${templateLabel(profile)} · ${isStateChanging(profile) ? 'State-changing' : 'Read-only'}` : 'Only compatible templates are shown.'}</small>
            </div>
            <button className="btn primary lg" disabled={allProfilesMode ? !canRunAll : !profile || !profile.available} onClick={next}>
              Configure scan <span aria-hidden="true">→</span>
            </button>
          </aside>
        </div>
      )}

      {adding && (
        <AddTarget
          onClose={() => setAdding(false)}
          onCreated={(created) => {
            onTargetCreated(created)
            selectTarget(created.target_ref)
            setAdding(false)
          }}
        />
      )}

      {step === 2 && profile && target && profile.engine === 'TOOLBOX' && (
        <BeastConsole
          embedded
          initialTargetRef={target.target_ref}
          initialScenario={TOOLBOX_SCENARIOS[profile.profile_id]}
          operatorProfileId={profile.profile_id}
          onBack={back}
        />
      )}

      {step === 2 && target && allProfilesMode && allToolboxProfiles && (
        <ToolboxCampaign
          target={target}
          profiles={targetProfiles}
          scenarios={TOOLBOX_SCENARIOS}
          onBack={back}
        />
      )}

      {step === 2 && target && allProfilesMode && !allToolboxProfiles && (
        <StandardCampaign
          target={target}
          profiles={targetProfiles}
          onStart={onStart}
          onOpenRun={onStarted}
          onBack={back}
        />
      )}

      {step === 2 && profile && target && profile.engine !== 'TOOLBOX' && (
        <div className="assessment-layout configure-layout">
          <main className="assessment-flow">
            <section className="scan-editor-head">
              <button className="btn ghost" type="button" onClick={back}>← Templates</button>
              <span className="template-icon" aria-hidden="true">{CATEGORY_MARKS[templateCategory(profile)]}</span>
              <div>
                <span className="section-kicker">{templateLabel(profile)} · {templateCategory(profile)}</span>
                <h2>{profile.display_name}</h2>
                <p>{target.name} · <span className="mono">{target.authorized_scope[0]}</span></p>
              </div>
            </section>
            <nav className="scan-editor-tabs" aria-label="Scan configuration sections">
              {([
                ['settings', 'Settings'],
                ['credentials', 'Credentials'],
                ['checks', 'Checks'],
                ['advanced', 'Advanced'],
              ] as [ConfigTab, string][]).map(([id, label]) => (
                <button
                  type="button"
                  key={id}
                  className={configTab === id ? 'active' : ''}
                  onClick={() => setConfigTab(id)}
                >
                  {label}
                </button>
              ))}
            </nav>

            {configTab === 'settings' && (
              <>
            <section className="assessment-section execution-section">
              <div className="assessment-section-head">
                <div>
                  <span className="section-kicker">Basic</span>
                  <h2>Execution controls</h2>
                  <p>Set limits for this run. Policy maximums cannot be exceeded.</p>
                </div>
                <Pill tone={isStateChanging(profile) ? 'critical' : 'success'}>
                  {isStateChanging(profile) ? 'Can change target state' : 'Read-only'}
                </Pill>
              </div>
              {isProduction(target) && (
                <div className="banner warning execution-warning">
                  <div className="banner-body">
                    <strong className="accent">Production target</strong>
                    Review the authorized scope, budget and exclusions before you start. This run is
                    bounded to exactly the origins and paths shown.
                  </div>
                </div>
              )}
              <div className="execution-limit-grid">
                <label className="field">
                  <span>Target request budget</span>
                  <input
                    type="number"
                    min={1}
                    max={cap?.request_budget}
                    step={1}
                    value={requestBudget}
                    onChange={(event) => setRequestBudget(event.target.value)}
                    aria-describedby="request-budget-help"
                  />
                  <small id="request-budget-help" className="muted">
                    Up to {cap?.request_budget ?? '—'} requests
                  </small>
                </label>
                <label className="field">
                  <span>Maximum duration</span>
                  <input
                    type="number"
                    min={0.1}
                    max={cap ? cap.time_budget_ms / 60_000 : undefined}
                    step={0.1}
                    value={durationMinutes}
                    onChange={(event) => setDurationMinutes(event.target.value)}
                    aria-describedby="duration-budget-help"
                  />
                  <small id="duration-budget-help" className="muted">
                    Up to {cap ? cap.time_budget_ms / 60_000 : '—'} minutes
                  </small>
                </label>
              </div>
              {!limitsValid && (requestBudget || durationMinutes) && (
                <p className="field-error">Enter values within the profile's policy maximums.</p>
              )}
              <div className="execution-policy-row">
                <div>
                  <span>Concurrency</span>
                  <strong>{cap?.concurrency_budget ?? '—'}</strong>
                </div>
                <div>
                  <span>Authentication</span>
                  <strong>{cap?.requires_authentication ? 'Stored reference' : 'None'}</strong>
                </div>
                <div>
                  <span>Mode</span>
                  <strong>{isActiveProbing(profile) ? 'Active' : 'Passive'}</strong>
                </div>
              </div>
            </section>

            <section className="assessment-section scope-section">
              <div className="assessment-section-head compact-head">
                <div>
                  <span className="section-kicker">Targets</span>
                  <h2>Scope &amp; guardrails</h2>
                  <p>Final boundary enforced by the controller.</p>
                </div>
              </div>
              <div className="scope-guardrail-grid">
                <div>
                  <h3>Authorized scope</h3>
                  <div className="scope-box mono">
                {target.authorized_scope.map((s) => (
                  <div key={s}>{s}</div>
                ))}
                {target.allowed_path_prefixes.length > 0 && (
                  <div className="muted micro">Paths: {target.allowed_path_prefixes.join(', ')}</div>
                )}
                {target.excluded_path_prefixes.length > 0 && (
                  <div className="muted micro">Excluded: {target.excluded_path_prefixes.join(', ')}</div>
                )}
                <div className="muted micro">Authorization: {target.authorization_reference}</div>
              </div>
                  <p className="isolation-copy"><strong>Isolation:</strong> {profile.isolation_boundary}</p>
                </div>
                <div className="guardrail-columns">
                  <div>
                    <h3>Allowed</h3>
                    <ul className="allow-list">
                <li>
                  Send controller-compiled {isStateChanging(profile) ? 'requests' : 'read-only requests'} within
                  the {limitsValid ? requestBudgetValue : cap?.request_budget} request budget
                </li>
                {usesCredentials(profile) && (
                  <li>Use the stored credential reference for authenticated requests</li>
                )}
                <li>Produce hypotheses and evidence for the independent verifier</li>
              </ul>
                  </div>
                  <div>
                    <h3>It is not allowed to</h3>
                    <ul className="deny-list">
                {!isStateChanging(profile) && <li>Send state-changing requests or write to the target</li>}
                <li>Reach any origin outside the authorized target</li>
                <li>Exceed the request budget or the execution timeout</li>
                <li>Confirm its own findings — only the Aegis verifier can</li>
              </ul>
                  </div>
                </div>
              </div>
            </section>
              </>
            )}

            {configTab === 'credentials' && (
              <section className="assessment-section config-detail-panel">
                <span className="section-kicker">Credentials</span>
                <h2>{usesCredentials(profile) ? 'Stored credential reference' : 'No credentials required'}</h2>
                <p>
                  {usesCredentials(profile)
                    ? 'This template resolves its approved credential reference inside the execution boundary. Secret values are never sent to the browser.'
                    : 'This template performs anonymous requests and does not resolve a credential reference.'}
                </p>
                <div className="config-fact-list">
                  <div><span>Target reference</span><strong className="mono">{target.target_ref}</strong></div>
                  <div><span>Authentication</span><strong>{usesCredentials(profile) ? 'Controller-managed' : 'None'}</strong></div>
                  <div><span>Browser exposure</span><strong>Never</strong></div>
                </div>
              </section>
            )}

            {configTab === 'checks' && (
              <section className="assessment-section config-detail-panel">
                <span className="section-kicker">Checks</span>
                <h2>Template capabilities</h2>
                <p>Checks are fixed by the selected controller profile and cannot be widened from the browser.</p>
                <div className="check-catalog">
                  {profile.capabilities.map((capability) => (
                    <div key={capability.capability_id}>
                      <span className="check-enabled">✓</span>
                      <div>
                        <strong>{capability.title}</strong>
                        <p>{capability.activity} · {plural(capability.request_budget, 'request')} · verifies {capability.verified_severity}</p>
                        <small className="mono">{capability.capability_id}</small>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="tool-row">
                  <span>Execution tools</span>
                  <strong>{toolLabels(profile).join(' · ')}</strong>
                </div>
              </section>
            )}

            {configTab === 'advanced' && (
              <section className="assessment-section config-detail-panel">
                <span className="section-kicker">Advanced</span>
                <h2>Execution boundary</h2>
                <p>{profile.how_it_runs}</p>
                <div className="config-fact-list">
                  <div><span>Engine</span><strong>{profile.engine}</strong></div>
                  <div><span>Execution mode</span><strong>{profile.execution_mode ?? 'STANDARD'}</strong></div>
                  <div><span>Concurrency ceiling</span><strong>{maxConcurrency(profile)}</strong></div>
                  <div><span>Target impact</span><strong>{isStateChanging(profile) ? 'State-changing possible' : 'Read-only'}</strong></div>
                </div>
                <div className="advanced-boundary"><strong>Isolation boundary</strong><p>{profile.isolation_boundary}</p></div>
              </section>
            )}

            {error && (
              <div className="banner critical assessment-start-error">
                <div className="banner-body">
                  <strong>The assessment could not be started</strong>
                  {error}
                </div>
              </div>
            )}
          </main>

          <aside className="launch-sidebar">
            <section className="launch-summary final-summary">
              <span className="section-kicker">Ready to launch</span>
              <h2>Run plan</h2>
              <div className="summary-selection">
                <div className="complete">
                  <span>Target</span>
                  <strong>{target.name}</strong>
                </div>
                <div className="complete">
                  <span>Assessment</span>
                  <strong>{profile.display_name}</strong>
                </div>
                <div className={limitsValid ? 'complete' : ''}>
                  <span>Limits</span>
                  <strong>{limitsValid ? `${plural(requestBudgetValue, 'request')} · ${durationMinutesValue} min` : 'Needs attention'}</strong>
                </div>
              </div>
              <div className="summary-impact">
                <span>Controller policy</span>
                <strong className={isStateChanging(profile) ? 'critical-text' : 'success-text'}>
                  {isStateChanging(profile) ? 'State changes permitted' : 'Read-only execution'}
                </strong>
                <p>Fresh evidence required before any finding is confirmed.</p>
              </div>
              <button className="btn primary lg launch-continue" disabled={!canStart} onClick={start}>
                {starting ? 'Starting…' : 'Start assessment'}
              </button>
              <button className="btn ghost launch-cancel" onClick={back} disabled={starting}>Back to templates</button>
            </section>
            {toolboxPanel}
          </aside>
        </div>
      )}
    </div>
  )
}
