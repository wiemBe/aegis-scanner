import { useMemo, useState } from 'react'
import type { ScopePreview, TargetCreate, TargetEntry, TargetType } from './api'
import { consoleApi } from './api'
import { Pill } from './components'

type Props = {
  onClose: () => void
  onCreated: (target: TargetEntry) => void
}

const TYPE_OPTIONS: { value: TargetType; label: string; help: string }[] = [
  { value: 'WEBSITE', label: 'Company website', help: 'A website or fully-qualified domain name.' },
  { value: 'API', label: 'API', help: 'One or more API base URLs, with optional OpenAPI document.' },
  { value: 'IP_CIDR', label: 'IP address or CIDR', help: 'A single authorized IP or an explicitly authorized range.' },
  { value: 'SYNTHETIC', label: 'Synthetic range target', help: 'An authorized in-lab synthetic origin.' },
]

const ENVIRONMENTS = ['PRODUCTION', 'STAGING', 'DEVELOPMENT', 'INTERNAL', 'SYNTHETIC'] as const

// One entry per line — the controller normalizes each and shows the exact scope before saving.
function lines(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((v) => v.trim())
    .filter(Boolean)
}

const REASON_COPY: Record<string, string> = {
  EMBEDDED_CREDENTIALS_FORBIDDEN: 'Remove the user:password@ credentials from the origin. Credentials are referenced separately, never placed in the target.',
  ORIGIN_NOT_A_URL: 'Enter an origin (host, optional port) — not a full URL with a path. Paths belong in allowed/excluded prefixes.',
  MALFORMED_ORIGIN: 'That origin could not be parsed. Use example.company.com or https://example.company.com.',
  MALFORMED_HOST: 'That hostname is not valid.',
  DUPLICATE_ORIGIN: 'That origin is already authorized in this or another target.',
  WILDCARD_REQUIRES_EXPLICIT_AUTHORIZATION: 'Tick “Authorize wildcard subdomains” to include *.company.com.',
  CIDR_REQUIRES_EXPLICIT_AUTHORIZATION: 'Tick “Authorize this CIDR range” to include a whole network.',
  METADATA_HOST_NOT_AUTHORIZED: 'Cloud metadata / link-local hosts are not available through onboarding.',
  OPENAPI_URL_OUTSIDE_SCOPE: 'The OpenAPI document URL must be inside one of the authorized origins.',
  AT_LEAST_ONE_ORIGIN_REQUIRED: 'Add at least one authorized origin.',
  AT_LEAST_ONE_ADDRESS_REQUIRED: 'Add at least one authorized IP or CIDR.',
  AUTHORIZATION_ATTESTATION_REQUIRED: 'Confirm you are authorized to assess these targets.',
}

function reason(code: string): string {
  return REASON_COPY[code] ?? code
}

export function AddTarget({ onClose, onCreated }: Props) {
  const [targetType, setTargetType] = useState<TargetType>('WEBSITE')
  const [displayName, setDisplayName] = useState('')
  const [environment, setEnvironment] = useState<(typeof ENVIRONMENTS)[number]>('PRODUCTION')
  const [owner, setOwner] = useState('')
  const [authRef, setAuthRef] = useState('')
  const [description, setDescription] = useState('')
  const [attested, setAttested] = useState(false)

  const [origins, setOrigins] = useState('')
  const [wildcards, setWildcards] = useState('')
  const [wildcardAuthorized, setWildcardAuthorized] = useState(false)
  const [openapiUrl, setOpenapiUrl] = useState('')
  const [credentialReference, setCredentialReference] = useState('')
  const [allowedPaths, setAllowedPaths] = useState('')
  const [excludedPaths, setExcludedPaths] = useState('')
  const [addresses, setAddresses] = useState('')
  const [cidrAuthorized, setCidrAuthorized] = useState(false)

  const [preview, setPreview] = useState<ScopePreview>()
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)

  const isNetworkScope = targetType === 'IP_CIDR'
  const isApi = targetType === 'API'

  const request = useMemo<TargetCreate>(() => {
    const body: TargetCreate = {
      target_type: targetType,
      display_name: displayName,
      environment,
      owner: owner || null,
      authorization_reference: authRef,
      authorization_attested: attested,
      description: description || null,
    }
    if (isNetworkScope) {
      body.addresses = lines(addresses)
      body.cidr_authorized = cidrAuthorized
    } else {
      body.origins = lines(origins)
      body.wildcard_subdomains = lines(wildcards)
      body.wildcard_authorized = wildcardAuthorized
      body.allowed_path_prefixes = lines(allowedPaths)
      body.excluded_path_prefixes = lines(excludedPaths)
      if (isApi) {
        body.openapi_url = openapiUrl || null
        body.credential_reference = credentialReference || null
      }
    }
    return body
  }, [
    targetType, displayName, environment, owner, authRef, attested, description,
    isNetworkScope, isApi, addresses, cidrAuthorized, origins, wildcards,
    wildcardAuthorized, allowedPaths, excludedPaths, openapiUrl, credentialReference,
  ])

  const canSubmit = Boolean(displayName.trim() && authRef.trim() && attested && !busy)

  const runPreview = async () => {
    setError(undefined)
    setBusy(true)
    try {
      setPreview(await consoleApi.previewTarget(request))
    } catch (e) {
      setPreview(undefined)
      setError(reason(e instanceof Error ? e.message : 'PREVIEW_FAILED'))
    } finally {
      setBusy(false)
    }
  }

  const save = async () => {
    setError(undefined)
    setBusy(true)
    try {
      const created = await consoleApi.createTarget(request)
      onCreated(created)
    } catch (e) {
      setError(reason(e instanceof Error ? e.message : 'CREATE_FAILED'))
      setBusy(false)
    }
  }

  return (
    <div className="modal-scrim" role="dialog" aria-modal="true" aria-label="Add authorized target">
      <div className="modal target-modal">
        <h2>Add authorized target</h2>
        <p>
          Add the exact company origins you are authorized to assess. Redirects and discovered hosts
          outside this scope will not be followed.
        </p>

        <div className="type-tabs" role="tablist">
          {TYPE_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              role="tab"
              type="button"
              aria-selected={targetType === opt.value}
              className={`type-tab ${targetType === opt.value ? 'active' : ''}`}
              onClick={() => {
                setTargetType(opt.value)
                setPreview(undefined)
              }}
            >
              {opt.label}
            </button>
          ))}
        </div>
        <p className="muted type-help">{TYPE_OPTIONS.find((o) => o.value === targetType)?.help}</p>

        <div className="form-grid">
          <label className="field">
            <span>Display name</span>
            <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Company Marketing Site" />
          </label>
          <label className="field">
            <span>Environment</span>
            <select value={environment} onChange={(e) => setEnvironment(e.target.value as typeof environment)}>
              {ENVIRONMENTS.map((env) => (
                <option key={env} value={env}>{env.charAt(0) + env.slice(1).toLowerCase()}</option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Business or technical owner (optional)</span>
            <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="platform-security@company.com" />
          </label>
          <label className="field">
            <span>Authorization reference</span>
            <input value={authRef} onChange={(e) => setAuthRef(e.target.value)} placeholder="CHG-1029 / ticket ID" />
          </label>
        </div>

        {!isNetworkScope && (
          <>
            <label className="field wide">
              <span>{isApi ? 'API base URLs' : 'Authorized origins'}</span>
              <textarea
                value={origins}
                onChange={(e) => setOrigins(e.target.value)}
                rows={isApi ? 3 : 2}
                placeholder={isApi ? 'https://api.company.com\nhttps://api.company.com:8443' : 'example.company.com\nhttps://shop.company.com'}
              />
            </label>
            <div className="form-grid">
              <label className="field">
                <span>Authorized subdomain scope (optional)</span>
                <input value={wildcards} onChange={(e) => setWildcards(e.target.value)} placeholder="*.company.com" />
              </label>
              <label className="check">
                <input type="checkbox" checked={wildcardAuthorized} onChange={(e) => setWildcardAuthorized(e.target.checked)} />
                <span>Authorize wildcard subdomains</span>
              </label>
            </div>
            <div className="form-grid">
              <label className="field">
                <span>Allowed path prefixes (optional)</span>
                <input value={allowedPaths} onChange={(e) => setAllowedPaths(e.target.value)} placeholder="/api, /v1" />
              </label>
              <label className="field">
                <span>Excluded paths</span>
                <input value={excludedPaths} onChange={(e) => setExcludedPaths(e.target.value)} placeholder="/admin, /internal" />
              </label>
            </div>
            {isApi && (
              <div className="form-grid">
                <label className="field">
                  <span>OpenAPI document URL (optional, in-scope)</span>
                  <input value={openapiUrl} onChange={(e) => setOpenapiUrl(e.target.value)} placeholder="https://api.company.com/openapi.json" />
                </label>
                <label className="field">
                  <span>Credential reference (optional)</span>
                  <input value={credentialReference} onChange={(e) => setCredentialReference(e.target.value)} placeholder="vault://payments-api/token" />
                </label>
              </div>
            )}
            {isApi && (
              <p className="muted micro">
                Never enter API keys, passwords or tokens here. Credentials are referenced through the
                controller-owned credential mechanism and stay controller-side.
              </p>
            )}
          </>
        )}

        {isNetworkScope && (
          <>
            <label className="field wide">
              <span>Authorized IPs / CIDRs</span>
              <textarea
                value={addresses}
                onChange={(e) => setAddresses(e.target.value)}
                rows={2}
                placeholder={'10.4.1.20\n10.4.0.0/24'}
              />
            </label>
            <label className="check">
              <input type="checkbox" checked={cidrAuthorized} onChange={(e) => setCidrAuthorized(e.target.checked)} />
              <span>Authorize this CIDR range</span>
            </label>
            <p className="muted micro">
              Internal and private address space is allowed when explicitly authorized and reachable
              from the approved execution environment.
            </p>
          </>
        )}

        <label className="field wide">
          <span>Description (optional)</span>
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What this target is and why it's in scope." />
        </label>

        <label className="check attest">
          <input type="checkbox" checked={attested} onChange={(e) => setAttested(e.target.checked)} />
          <span>I confirm that I am authorized to assess these targets</span>
        </label>

        {preview && (
          <div className="scope-review">
            <div className="panel-head">
              <h3>Normalized authorized scope</h3>
              <Pill tone="neutral">Review before saving</Pill>
            </div>
            <ul className="scope-list">
              {preview.authorized_scope.map((s) => (
                <li key={s} className="mono">{s}</li>
              ))}
            </ul>
            {preview.excluded_path_prefixes.length > 0 && (
              <p className="muted micro">Excluded: {preview.excluded_path_prefixes.join(', ')}</p>
            )}
            {preview.openapi_url && <p className="muted micro">OpenAPI: {preview.openapi_url}</p>}
          </div>
        )}

        {error && (
          <div className="banner critical" style={{ marginTop: 14 }}>
            <div className="banner-body">
              <strong>The target could not be saved</strong>
              {error}
            </div>
          </div>
        )}

        <div className="modal-actions">
          <button className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn" onClick={runPreview} disabled={!canSubmit}>Preview scope</button>
          <button className="btn primary" onClick={save} disabled={!canSubmit}>Add and continue</button>
        </div>
      </div>
    </div>
  )
}
