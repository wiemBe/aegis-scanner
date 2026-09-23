import type { ReactNode } from 'react'
import type { RunStatus } from './api'
import { runStateView } from './format'
import type { Tone } from './format'

export function Pill({ tone = 'neutral', running, children }: { tone?: Tone; running?: boolean; children: ReactNode }) {
  return <span className={`pill ${tone}${running ? ' running' : ''}`}>{children}</span>
}

export function RunStatePill({ status }: { status: RunStatus }) {
  const view = runStateView(status)
  return (
    <Pill tone={view.tone} running={view.running}>
      {view.label}
    </Pill>
  )
}

export function HealthDot({ state, label }: { state: 'ok' | 'warn' | 'bad' | 'unknown'; label: string }) {
  return (
    <span className={`health-dot ${state}`} title={label}>
      <i />
      {label}
    </span>
  )
}

export function Empty({ title, copy, action }: { title: string; copy: string; action?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      <p>{copy}</p>
      {action}
    </div>
  )
}

export function Loading({ label = 'Loading verified records…' }: { label?: string }) {
  return <div className="loading">{label}</div>
}

export function Kv({ items, wide }: { items: [string, ReactNode][]; wide?: boolean }) {
  return (
    <dl className={`kv${wide ? ' wide' : ''}`}>
      {items.map(([term, value]) => (
        <div style={{ display: 'contents' }} key={term}>
          <dt>{term}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  )
}
