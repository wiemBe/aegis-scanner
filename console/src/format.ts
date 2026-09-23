import type { Run, RunStatus } from './api'

export type Tone = 'success' | 'warning' | 'critical' | 'neutral'

// Run lifecycle state, mapped to an operator-readable label + state colour.
export function runStateView(status: RunStatus): { label: string; tone: Tone; running: boolean } {
  switch (status) {
    case 'RUNNING':
      return { label: 'Running', tone: 'warning', running: true }
    case 'QUEUED':
      return { label: 'Queued', tone: 'warning', running: true }
    case 'PASS':
      return { label: 'Pass', tone: 'success', running: false }
    case 'FAIL':
      return { label: 'Findings', tone: 'critical', running: false }
    case 'REVIEW':
      return { label: 'Review', tone: 'neutral', running: false }
    case 'INCOMPLETE':
      return { label: 'Incomplete', tone: 'neutral', running: false }
    default:
      return { label: status, tone: 'neutral', running: false }
  }
}

// A finding is CONFIRMED, a hypothesis is UNCONFIRMED, a clean retest is PASS, otherwise UNKNOWN.
export function findingStateView(finding: {
  confidence: string
  status: string
  final_state: string
}): { label: string; tone: Tone } {
  if (finding.status === 'REMEDIATED' || finding.final_state === 'PASS') return { label: 'PASS', tone: 'success' }
  if (finding.confidence === 'CONFIRMED') return { label: 'CONFIRMED FINDING', tone: 'critical' }
  if (finding.confidence === 'HYPOTHESIS' || finding.status === 'UNCONFIRMED')
    return { label: 'UNCONFIRMED HYPOTHESIS', tone: 'warning' }
  return { label: 'UNKNOWN', tone: 'neutral' }
}

export const short = (value: string | null | undefined, size = 16) =>
  value ? (value.length > size ? `${value.slice(0, size)}…` : value) : '—'

export const when = (value: string | null | undefined) =>
  value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—'

export const time = (value: string | null | undefined) =>
  value ? new Date(value).toLocaleTimeString() : '—'

export function elapsed(run?: Pick<Run, 'created_at' | 'completed_at'>): string {
  if (!run) return '—'
  const end = run.completed_at ? new Date(run.completed_at).getTime() : Date.now()
  const seconds = Math.max(0, Math.round((end - new Date(run.created_at).getTime()) / 1000))
  if (seconds < 1) return '<1s'
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`
}
