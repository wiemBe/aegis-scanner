const button = document.querySelector('#run-scan');
const retestButton = document.querySelector('#retest');
const statusEl = document.querySelector('#status');
const notice = document.querySelector('#notice');
let selectedScan = null;
let polling;
let generation = 0;

const escapeHtml = (value) => String(value ?? '')
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;').replaceAll("'", '&#039;');
const pretty = (value) => escapeHtml(JSON.stringify(value, null, 2));

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) throw new Error(`Request failed (HTTP ${response.status}).`);
  return response.json();
}

function render(payload) {
  const scan = payload.scan;
  selectedScan = scan;
  statusEl.textContent = scan.status;
  statusEl.className = `badge ${scan.status.toLowerCase()}`;
  const running = ['QUEUED', 'RUNNING'].includes(scan.status);
  button.disabled = running;
  retestButton.disabled = running || scan.status !== 'FAIL' || scan.variant !== 'vulnerable';
  document.querySelector('#empty').classList.add('hidden');
  document.querySelector('#scan-detail').classList.remove('hidden');
  document.querySelector('#scan-id').textContent = scan.id;
  document.querySelector('#planner').textContent = `${scan.planner}${scan.model ? ` · ${scan.model}` : ''}`;
  const mode = scan.mode || scan.planner;
  const isLive = mode !== 'DEMO_HEURISTIC';
  const modeEl = document.querySelector('#mode-label');
  modeEl.textContent = mode;
  modeEl.className = isLive ? 'mode-live' : 'mode-demo';
  const meta = scan.provider_metadata || {};
  const digest = meta.model_digest ? ` · digest ${escapeHtml(String(meta.model_digest).slice(0, 19))}…` : '';
  document.querySelector('#provider').textContent = isLive
    ? `PROVIDER: ${escapeHtml(meta.runtime || '—')}${meta.runtime_version ? ' ' + escapeHtml(meta.runtime_version) : ''} · model ${escapeHtml(scan.model || '—')}${digest} · ctx ${meta.context_length ?? '—'} · temp ${meta.temperature ?? '—'} · seed ${meta.seed ?? '—'} · last call ${meta.total_duration_ms ?? '—'}ms · stop ${escapeHtml(meta.stop_reason || '—')} · provider tokens in/out ${meta.prompt_eval_count ?? '—'}/${meta.eval_count ?? '—'}`
    : 'NO PROVIDER EGRESS · offline heuristic planner · reported tokens always 0';
  const h = scan.hypotheses.at(-1);
  const hypothesisSource = scan.retest_of
    ? 'DETERMINISTIC LINKED RETEST · controller-constructed from the confirmed finding'
    : (isLive
        ? 'AI-GENERATED HYPOTHESIS (candidate) → DETERMINISTICALLY COMPILED READ-ONLY TEST'
        : 'HEURISTIC HYPOTHESIS (candidate) → DETERMINISTICALLY COMPILED READ-ONLY TEST');
  document.querySelector('#hypothesis').innerHTML = h ? `
    <small>${hypothesisSource} · ${escapeHtml(h.category)}</small>
    <h3>${escapeHtml(h.title)}</h3><p>${escapeHtml(h.rationale)}</p>` : '<p>No approved hypothesis yet.</p>';
  document.querySelector('#verification').textContent = `DETERMINISTIC VERIFICATION: ${scan.verification?.summary || 'Pending'}`;
  document.querySelector('#protocol').textContent = `CONTRACT v${scan.planner_contract_version ?? '—'} · Execution policy v${scan.execution_policy_version ?? '—'} · Scenario: ${scan.scenario || '—'} · AI candidates generated/validated/rejected: ${scan.generated_candidates_total ?? 0}/${scan.validated_candidates_total ?? 0}/${scan.rejected_candidates_total ?? 0} · Deterministically executed candidate(s): ${(scan.executed_candidate_ids || []).join(', ') || '—'} · Validated blocker: ${scan.validated_blocker || '—'} · Target requests: ${scan.evidence.length} · Verifier-confirmed findings: ${scan.findings.length} · Exact terminal: ${scan.terminal_reason || '—'}`;
  document.querySelector('#budget').textContent = `Requests (including OpenAPI import): ${scan.usage.requests} · Iterations: ${scan.usage.iterations} · Model calls: ${scan.usage.model_calls} · Token reservations: ${scan.usage.reserved_tokens} · Provider-reported tokens: ${scan.usage.reported_tokens} · Stop: ${scan.stop_reason || '—'}`;
  document.querySelector('#retest-link').textContent = `Variant: ${scan.variant}${scan.retest_of ? ` · Fresh retest of ${scan.retest_of}` : ''}. PASS covers only the tested synthetic authorization comparison.`;
  notice.textContent = scan.error ? `Scan stopped: ${scan.error}` : '';
  document.querySelector('#finding-count').textContent = scan.findings.length;
  document.querySelector('#findings').innerHTML = scan.findings.length ? scan.findings.map(f => `
    <div class="finding"><div><span class="severity">${escapeHtml(f.severity)}</span><span>${escapeHtml(f.confidence)}</span></div>
    <h3>${escapeHtml(f.title)}</h3><p>${escapeHtml(f.description)}</p><p>Remediation: ${escapeHtml(f.remediation)}</p>
    <small>Evidence: ${escapeHtml(f.evidence_names.join(', '))}</small></div>`).join('') : '<p>No confirmed finding. See verification for coverage.</p>';
  document.querySelector('#evidence').innerHTML = scan.evidence.map(e => `
    <details><summary>${escapeHtml(e.name)} · ${escapeHtml(e.status_code ?? 'ERR')} · ${escapeHtml(e.credential_profile)}</summary>
    <pre>${pretty(e)}</pre></details>`).join('') || '<p>No tests executed.</p>';
  const candidateRecords = (scan.candidate_records || []).map((r, i) => {
    const admitted = (r.queue || []).filter(q => q.admitted).map(q => q.candidate_id);
    const label = r.stage === 'retest'
      ? 'DETERMINISTIC LINKED RETEST'
      : (r.terminal_reason && r.executed_candidate_ids.length === 0
          ? `DETERMINISTIC OUTCOME · ${String(r.terminal_reason).toUpperCase()}`
          : 'AI HYPOTHESES → DETERMINISTIC VALIDATION & EXECUTION ADMISSION');
    return `
    <div class="decision"><strong>Stage ${i + 1} · ${escapeHtml(label)}</strong>
    <p>AI candidates generated ${r.generated} · deterministically validated ${r.validated_ids.length} · rejected ${r.rejections.length}
     · execution policy v${escapeHtml(r.execution_policy_version ?? '—')} · admitted ${escapeHtml(admitted.join(', ') || '—')} · executed ${escapeHtml((r.executed_candidate_ids || []).join(', ') || '—')}</p>
    <details><summary>Structured controller record (validation, queue, admission)</summary><pre>${pretty(r)}</pre></details></div>`;
  }).join('');
  document.querySelector('#decisions').innerHTML = candidateRecords + scan.decisions.map((d, i) => `
    <div class="decision"><strong>${i + 1} · ${escapeHtml(String(d.decision_type).toUpperCase())} (deterministic controller)</strong><p>${escapeHtml(d.summary)}</p>
    ${d.hypothesis ? `<details><summary>Deterministically compiled read-only test</summary><pre>${pretty(d.hypothesis)}</pre></details>` : ''}</div>`).join('') +
    `<h3>Safety decisions</h3><pre>Planner Contract v${escapeHtml(scan.planner_contract_version ?? '—')}${scan.repair_attempts ? ` · repair attempts: ${escapeHtml(scan.repair_attempts)}` : ''}\n${escapeHtml(scan.safety_events.join('\n') || 'Pending')}</pre>`;
  document.querySelector('#audit').innerHTML = payload.audit.map(a => `
    <div><time>${escapeHtml(a.created_at.slice(11, 19))}</time><details><summary>${escapeHtml(a.event)}</summary><pre>${pretty(a.details)}</pre></details></div>`).join('');
}

async function history() {
  const scans = await api('/api/scans');
  document.querySelector('#history').innerHTML = scans.map(s => `<button class="history-item" data-scan="${escapeHtml(s.id)}">${escapeHtml(s.id)} · ${escapeHtml(s.variant)} · ${escapeHtml(s.status)}${s.retest_of ? ' · RETEST' : ''}</button>`).join('');
  return scans;
}

async function select(id) {
  const current = ++generation;
  clearTimeout(polling);
  async function poll() {
    try {
      const payload = await api(`/api/scans/${encodeURIComponent(id)}`);
      if (current !== generation) return;
      render(payload);
      if (['QUEUED', 'RUNNING'].includes(payload.scan.status)) polling = setTimeout(poll, 700);
      else await history();
    } catch (error) {
      if (current !== generation) return;
      notice.textContent = error.message;
      button.disabled = false;
      retestButton.disabled = true;
    }
  }
  await poll();
}

async function start(retest) {
  button.disabled = true;
  retestButton.disabled = true;
  notice.textContent = 'Starting bounded scan…';
  try {
    const body = {target: 'synthetic-bank-api', variant: retest ? 'patched' : 'vulnerable'};
    if (retest) body.retest_of = selectedScan.id;
    const scan = await api('/api/scans', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    await select(scan.id);
  } catch (error) {
    notice.textContent = error.message;
    button.disabled = false;
  }
}
button.addEventListener('click', () => start(false));
retestButton.addEventListener('click', () => start(true));
document.querySelector('#history').addEventListener('click', (event) => {
  const item = event.target.closest('[data-scan]');
  if (item) select(item.dataset.scan);
});
history().then(scans => { if (scans.length) return select(scans[0].id); }).catch(error => { notice.textContent = error.message; });
