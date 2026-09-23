"use strict";

const text = (value) => document.createTextNode(String(value ?? "—"));

function metric(label, value) {
  const node = document.createElement("div");
  node.className = "metric";
  const name = document.createElement("span");
  name.append(text(label));
  const result = document.createElement("strong");
  result.append(text(value));
  node.append(name, result);
  return node;
}

function render(run) {
  const article = document.createElement("article");
  article.className = "run";
  const title = document.createElement("h2");
  title.append(text(`${run.run_id} · ${run.scenario_id}`));
  const grid = document.createElement("div");
  grid.className = "grid";
  grid.append(
    metric("State", run.state),
    metric("Mode", run.execution_mode),
    metric("Active role", run.active_role),
    metric("Tasks", run.tasks.length),
    metric("Hypotheses", run.validated_hypotheses),
    metric("Verifier result", run.verifier_findings[0]?.status),
    metric("Model calls", run.metrics.model_calls),
    metric("Target requests", run.metrics.target_requests),
    metric("Tokens", run.metrics.input_tokens + run.metrics.output_tokens),
    metric("Cleanup", run.cleanup_succeeded ? "VERIFIED" : "NOT VERIFIED"),
    metric("Stop", run.stop_requested ? "REQUESTED" : "NOT REQUESTED")
  );
  article.append(title, grid);
  return article;
}

async function load() {
  const status = document.querySelector("#status");
  const runs = document.querySelector("#runs");
  try {
    const response = await fetch("/api/console/multi-agent/runs", { credentials: "same-origin" });
    if (!response.ok) throw new Error("request failed");
    const body = await response.json();
    status.textContent = `${body.items.length} bounded run record(s)`;
    if (body.items.length === 0) {
      const empty = document.createElement("p");
      empty.append(text("No Phase 1.7 runs have been persisted yet."));
      runs.append(empty);
      return;
    }
    body.items.forEach((item) => runs.append(render(item)));
  } catch (_) {
    status.textContent = "Run records unavailable";
  }
}

load();
