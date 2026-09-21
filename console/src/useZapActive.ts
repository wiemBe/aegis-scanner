import { useCallback, useEffect, useRef, useState } from 'react'
import type { ZapActiveConfig, ZapActivePreflight, ZapActiveSession } from './ZapActive'

// State and polling for the Phase 1.5 ZAP Active view. Kept out of the component file so the
// view module exports components only. Every value it holds is already redacted by the
// controller: there is no code path here that could receive a token, payload or response body.

export function useZapActive(apiGet: <T>(path: string) => Promise<T>, apiPost: <T>(path: string, body: Record<string, unknown>) => Promise<T>) {
  const [config, setConfig] = useState<ZapActiveConfig>()
  const [preflight, setPreflight] = useState<ZapActivePreflight>()
  const [session, setSession] = useState<ZapActiveSession>()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const [authRequired, setAuthRequired] = useState(false)
  const refreshSequence = useRef(0)

  const acceptSession = useCallback((next: ZapActiveSession) => {
    setSession((current) => current?.state === 'STOPPED' && next.state !== 'STOPPED' ? current : next)
  }, [])

  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current
    try {
      const next = await apiGet<ZapActiveConfig>('/api/zap-active/config')
      if (sequence !== refreshSequence.current) return
      setConfig(next)
      if (!next.enabled) return
      const [nextPreflight, nextSession] = await Promise.all([
        apiGet<ZapActivePreflight>('/api/zap-active/preflight'),
        apiGet<ZapActiveSession>('/api/zap-active/session'),
      ])
      if (sequence !== refreshSequence.current) return
      setPreflight(nextPreflight)
      acceptSession(nextSession)
      setAuthRequired(false)
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : 'ZAP Active status unavailable'
      setAuthRequired(/\((401|403)\)/.test(message) || message.includes('OPERATOR_AUTH_REQUIRED'))
      setError(message)
    }
  }, [acceptSession, apiGet])

  useEffect(() => { void refresh() }, [refresh])
  useEffect(() => {
    if (!config?.enabled) return undefined
    const timer = window.setInterval(() => void refresh(), 2000)
    return () => window.clearInterval(timer)
  }, [config?.enabled, refresh])

  const login = useCallback(async (bootstrap_secret: string) => {
    setBusy(true)
    try {
      const result = await apiPost<{ csrf_token: string }>('/api/zap-active/operator/login', { bootstrap_secret })
      sessionStorage.setItem('aegis-zap-active-csrf', result.csrf_token)
      setAuthRequired(false)
      await refresh()
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Operator authentication failed') }
    finally { setBusy(false) }
  }, [apiPost, refresh])

  const activate = useCallback(async (scenario: string, confirmation_phrase: string) => {
    setBusy(true)
    try { acceptSession(await apiPost<ZapActiveSession>('/api/zap-active/activate', { scenario, confirmation_phrase, operator_id: 'local-operator' })) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Activation rejected') }
    finally { setBusy(false); void refresh() }
  }, [acceptSession, apiPost, refresh])

  const run = useCallback(async () => {
    setBusy(true)
    try { acceptSession(await apiPost<ZapActiveSession>('/api/zap-active/run', {})) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Execution refused') }
    finally { setBusy(false); void refresh() }
  }, [acceptSession, apiPost, refresh])

  const stop = useCallback(async () => {
    try { acceptSession(await apiPost<ZapActiveSession>('/api/zap-active/stop', { operator_id: 'local-operator' })) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Emergency stop failed') }
    finally { void refresh() }
  }, [acceptSession, apiPost, refresh])

  return { config, preflight, session, busy, error, authRequired, refresh, login, activate, run, stop }
}
