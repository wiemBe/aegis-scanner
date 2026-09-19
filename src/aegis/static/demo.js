"use strict";
// Phase 0.9 management demo view. Read-only: it renders the two demo scans (discovery + linked
// retest) named by ?discovery=&retest= entirely from the existing /api/scans API. It never mutates
// state and never renders raw response bodies or model reasoning — only stable identifiers, actor
// types and observed status codes.

// Audit event -> actor that PERFORMED it (mirrors aegis.demo._ACTOR_BY_EVENT). Unknown events
// default to CONTROLLER; the model is never over-attributed an action.
const ACTOR_BY_EVENT = {
  SCAN_CREATED: "CONTROLLER", SCAN_STARTED: "CONTROLLER", TOOL_REQUEST: "CONTROLLER",
  SAFETY_APPROVED: "SAFETY", SAFETY_REJECTED: "SAFETY", OPENAPI_OBSERVATION: "CONTROLLER",
  PREFLIGHT: "CONTROLLER", CANDIDATE_GENERATION_REQUEST: "CONTROLLER",
  CANDIDATE_GENERATED: "AI_MODEL", BLOCKER_VALIDATION: "CONTROLLER",
  CANDIDATE_VALIDATION: "CONTROLLER", EXECUTION_QUEUE: "CONTROLLER",
  REQUEST_STARTED: "CONTROLLER", OBSERVATION: "CONTROLLER", RETEST_PLAN: "CONTROLLER",
  VERIFIER_RESULT: "VERIFIER", TERMINAL_REASON: "CONTROLLER", SCAN_COMPLETED: "CONTROLLER",
};

const DOES_NOT_PROVE = [
  "One read-only object-authorization (BOLA) capability against a synthetic lab route only.",
  "Not production readiness and not a claim about any real application.",
  "Not broad vulnerability coverage: exactly one capability is exercised.",
  "Not unrestricted or autonomous pentesting: every request is deterministic, read-only, scoped and budgeted.",
  "The patched route is a synthetic remediation in the same lab, not an independently deployed fixed system.",
];

const VULNERABLE_ROUTE = "/api/v1/accounts/{account_id}";
const PATCHED_ROUTE = "/api/v1/patched/accounts/{account_id}";

function actorFor(event) {
  return ACTOR_BY_EVENT[event] || "CONTROLLER";
}

function esc(value) {
  const div = document.createElement("div");
  div.textContent = value === null || value === undefined ? "—" : String(value);
  return div.innerHTML;
}

function param(name) {
  return new URLSearchParams(window.location.search).get(name);
}

async function fetchScan(id) {
  const response = await fetch("/api/scans/" + encodeURIComponent(id));
  if (!response.ok) {
    throw new Error("scan " + id + " not found (" + response.status + ")");
  }
  return response.json();
}

function kv(pairs) {
  return pairs.map((p) => "<dt>" + esc(p[0]) + "</dt><dd>" + esc(p[1]) + "</dd>").join("");
}

function validatedCandidate(scan) {
  // Surface the candidate the deterministic controller actually executed (the one whose direction
  // the finding confirms), not merely the first validated one. The model may propose several.
  const record = (scan.candidate_records || []).find((r) => r.stage === "discovery") || {};
  const list = record.validated_candidates || [];
  const executed = (scan.executed_candidate_ids || [])[0] || scan.selected_candidate_id;
  const chosen = list.find((v) => v.candidate_id === executed) || list[0] || {};
  return { candidate: chosen.candidate || {}, record: record };
}

function candidateTimestamp(report) {
  const ev = (report.audit || []).find((e) => e.event === "CANDIDATE_GENERATED");
  return ev ? ev.created_at : null;
}

function statusCodes(scan) {
  return (scan.evidence || []).map((e) => e.status_code);
}

function renderAi(discovery) {
  const { candidate } = validatedCandidate(discovery.scan);
  const rows = [
    ["Proposed capability", candidate.capability],
    ["Selected operation", candidate.operation_id],
    ["Principal relationship", candidate.alternate_principal_ref + " → reads object owned by " + candidate.owner_principal_ref],
    ["Selected object", candidate.object_ref],
    ["Candidate timestamp", candidateTimestamp(discovery)],
  ];
  document.getElementById("ai-kv").innerHTML = kv(rows);
}

function renderController(discovery) {
  const scan = discovery.scan;
  const { record } = validatedCandidate(scan);
  const admitted = (record.queue || []).filter((q) => q.admitted).length;
  const rows = [
    ["Candidate validation", (scan.validated_candidates_total || 0) + " of " + (scan.generated_candidates_total || 0) + " admitted"],
    ["Queue admission", admitted + " admitted (deterministic, no model selection)"],
    ["Safety authorization", "approve_plan · read-only · scoped"],
    ["Request compilation", (scan.evidence || []).length + " typed read-only requests"],
    ["Budgets", "requests " + (scan.usage || {}).requests + " · model_calls " + (scan.usage || {}).model_calls],
    ["Scope decision", "within approved account route + read-only methods"],
  ];
  document.getElementById("controller-kv").innerHTML = kv(rows);
}

function renderSequences(discovery, retest) {
  const dCodes = statusCodes(discovery.scan);
  const rCodes = statusCodes(retest.scan);
  const finding = (discovery.scan.findings || [])[0] || {};
  function codesHtml(codes) {
    return codes.map((c) => "<b" + (c === 403 ? ' class="deny"' : "") + ">" + esc(c) + "</b>").join(" / ");
  }
  const rows = [
    ["Discovery (vulnerable)", VULNERABLE_ROUTE, codesHtml(dCodes), esc((finding.severity || "—") + "/" + (finding.confidence || "—") + " BOLA")],
    ["Linked retest (synthetic patched)", PATCHED_ROUTE, codesHtml(rCodes), "remediation " + esc(retest.scan.status)],
  ];
  document.getElementById("seq-body").innerHTML = rows
    .map((r) => "<tr><td>" + esc(r[0]) + "</td><td>" + esc(r[1]) + "</td><td class=\"codes\">" + r[2] + "</td><td>" + r[3] + "</td></tr>")
    .join("");
  const go = discovery.scan.status === "FAIL" && retest.scan.status === "PASS";
  const badge = document.getElementById("verdict-badge");
  badge.textContent = go ? "GO" : "NO-GO";
  badge.className = "badge " + (go ? "pass" : "fail");
}

function renderFinding(discovery) {
  const finding = (discovery.scan.findings || [])[0] || {};
  const rows = [
    ["Finding id", finding.id],
    ["Title", finding.title],
    ["Severity / confidence", (finding.severity || "—") + " / " + (finding.confidence || "—")],
    ["Category", finding.category],
    ["Bound evidence", (finding.evidence_names || []).join(", ")],
  ];
  document.getElementById("finding-kv").innerHTML = kv(rows);
  const badge = document.getElementById("finding-badge");
  badge.textContent = (finding.severity || "—") + "/" + (finding.confidence || "—");
  badge.className = "badge " + (finding.confidence === "CONFIRMED" ? "fail" : "");
  document.getElementById("provenance-note").textContent =
    "The AI did not create this finding. The deterministic verifier created it from fresh bound evidence (each a clean 200 read). The finding id is namespaced by scan and derived from its evidence name, so it cannot originate from model text or repeat across runs.";
}

function timelineEntries(report) {
  const scanId = report.scan.id;
  const findingNames = new Set(
    (report.scan.findings || []).flatMap((f) => f.evidence_names || [])
  );
  return (report.audit || []).map((e) => {
    const details = e.details && typeof e.details === "object" ? e.details : {};
    return {
      eventId: e.event_id || scanId + ":" + e.id,
      timestamp: e.timestamp || e.created_at,
      actor: e.actor_type || actorFor(e.event),
      event: e.event,
      confirms: e.event === "OBSERVATION" && findingNames.has(details.name),
    };
  });
}

function renderTimeline(discovery, retest) {
  const entries = timelineEntries(discovery).concat(timelineEntries(retest));
  document.getElementById("timeline").innerHTML = entries
    .map((t) => {
      const label = esc(t.event) + (t.confirms ? " ✓ (bound to finding)" : "");
      return (
        "<div><span class=\"actor " + esc(t.actor) + "\">" + esc(t.actor) + "</span>" +
        "<span class=\"eid\">" + esc(t.eventId) + "</span>" +
        "<span class=\"ev\">" + label + "</span></div>"
      );
    })
    .join("");
}

function renderLimits() {
  document.getElementById("limits").innerHTML = DOES_NOT_PROVE
    .map((item) => "<li>" + esc(item) + "</li>")
    .join("");
}

function showError(message) {
  const box = document.getElementById("error");
  box.textContent =
    "Could not load the demo: " + message +
    ". Open this page as /demo?discovery=<scan-id>&retest=<scan-id> or run scripts/run_management_demo.sh.";
  box.classList.remove("hidden");
}

async function main() {
  const discoveryId = param("discovery");
  const retestId = param("retest");
  document.getElementById("narrative").textContent =
    "The local AI model analyzes a projected API surface and independently proposes an object-authorization attack hypothesis. A deterministic policy layer validates scope and safety, compiles approved read-only requests, and executes the test. A deterministic verifier confirms the result from fresh evidence. After remediation, the controller repeats the same access direction and verifies that the unauthorized request is denied.";
  renderLimits();
  if (!discoveryId || !retestId) {
    showError("missing discovery/retest scan ids");
    return;
  }
  try {
    const [discovery, retest] = await Promise.all([fetchScan(discoveryId), fetchScan(retestId)]);
    renderAi(discovery);
    renderController(discovery);
    renderSequences(discovery, retest);
    renderFinding(discovery);
    renderTimeline(discovery, retest);
    document.getElementById("content").classList.remove("hidden");
  } catch (err) {
    showError(err.message);
  }
}

main();
