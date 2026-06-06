const state = {
  inputs: null,
  latest: null,
  savedRunId: null,
  history: [],
  historySearch: "",
  historyFilter: "all"
};

const inputConfig = [
  ["compiled_authority", "Compiled authority"],
  ["execution_request", "Execution request"],
  ["runtime_evidence", "Runtime evidence"],
  ["continuity_posture", "Continuity posture"]
];
const outcomeContractSchema = "guard_enforcement_outcome.v1";
const storageKeys = {
  tab: "waveframe.guard.activeTab",
  filter: "waveframe.guard.chronologyFilter",
  scroll: "waveframe.guard.scrollState"
};
const tabAliases = {
  trace: "explainability",
  "runtime-data": "developer-mode"
};
const scrollState = JSON.parse(sessionStorage.getItem(storageKeys.scroll) || "{}");

const byId = (id) => document.getElementById(id);
const formatJson = (value) => JSON.stringify(value, null, 2);
const escapeHtml = (value) => String(value)
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

const summarize = (value) => {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(summarize).join("; ");
  if (value && typeof value === "object") {
    return Object.entries(value)
      .filter(([, item]) => item !== null && item !== undefined)
      .map(([key, item]) => `${key}: ${summarize(item)}`)
      .join(", ");
  }
  return String(value);
};

async function loadSampleInputs() {
  const sample = byId("sampleSelect").value;
  setStatus("Loading example input set");
  const response = await fetch(`/api/runtime/inputs?sample=${encodeURIComponent(sample)}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`Input load failed: ${response.status}`);
  state.inputs = await response.json();
  byId("exampleLabel").textContent = state.inputs.sample_label || "Artifact Intake";
  renderInputDrawers(state.inputs);
  state.latest = null;
  state.savedRunId = null;
  byId("runRef").textContent = "no saved run";
  setStatus("Example inputs loaded. Evaluate when ready.");
  await refreshHistory();
}

async function evaluateCurrentInputs() {
  updateIntakeChecklist();
  if (!requiredInputsPresent()) {
    setStatus("Load compiled authority, execution request, and runtime evidence before evaluation");
    return;
  }
  setStatus("Evaluating execution");
  const payload = readInputDrawers();
  const response = await fetch("/api/runtime/evaluate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.message || body.error || "Evaluation failed");
  state.latest = body;
  renderEvaluation(body);
  setStatus(`Rendered ${body.guard_enforcement_outcome.schema_version || outcomeContractSchema}`);
}

async function saveCurrentRun() {
  if (!state.latest) throw new Error("Evaluate execution before saving a run");
  setStatus("Saving local run");
  const response = await fetch("/api/runtime/save", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(state.latest)
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.message || body.error || "Save run failed");
  state.savedRunId = body.saved_run.run_id;
  byId("runRef").textContent = state.savedRunId;
  renderReceipt(body.saved_run.receipt);
  await refreshHistory();
  setStatus(`Saved local run ${state.savedRunId}`);
}

async function replaySavedRun() {
  if (!state.savedRunId) throw new Error("Save a run before replay");
  setStatus("Replaying saved run");
  const response = await fetch("/api/runtime/replay", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ run_id: state.savedRunId })
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.message || body.error || "Replay run failed");
  state.latest = body;
  renderEvaluation(body);
  renderReceipt(receiptForRun(state.savedRunId));
  setStatus(body.replay.matches ? "Replay matched saved outcome" : "Replay differed from saved outcome");
}

async function exportCurrentReceipt() {
  if (!state.latest) throw new Error("Evaluate execution before exporting a receipt");
  setStatus("Exporting enforcement receipt");
  const response = await fetch("/api/runtime/export_receipt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(state.latest)
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.message || body.error || "Export receipt failed");
  downloadJson(body.receipt, `${body.receipt.run_id}.receipt.json`);
  renderReceipt(body.receipt);
  setStatus(`Exported receipt ${body.receipt.run_id}`);
}

async function refreshHistory() {
  const response = await fetch("/api/runtime/history", { cache: "no-store" });
  if (!response.ok) return;
  const body = await response.json();
  state.history = body.evaluations || [];
  renderHistory(state.history);
}

async function loadMostRecentRun() {
  await refreshHistory();
  if (!state.history.length) throw new Error("No saved SDK runs found in .guard-local");
  await loadSavedRun(state.history[0].run_id);
}

async function loadSavedRun(runId) {
  setStatus(`Loading saved run ${runId}`);
  const response = await fetch("/api/runtime/load_run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ run_id: runId })
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.message || body.error || "Load run failed");
  state.latest = body;
  state.savedRunId = runId;
  byId("runRef").textContent = runId;
  renderInputDrawers(body.inputs);
  renderEvaluation(body);
  renderReceipt(body.saved_run.receipt);
  setStatus(`Loaded saved run ${runId}`);
}

function renderInputDrawers(inputs) {
  byId("payloadDrawers").innerHTML = `
    <details class="advanced-json">
      <summary>Advanced JSON inputs</summary>
      <div class="advanced-json-note">Schemas are preserved for debugging and integration tests. Normal use starts from a Guard SDK run, saved receipt, or evaluation artifact.</div>
      <div class="schema-drawer-stack">
        ${inputConfig
    .map(([key, title]) => `
      <details>
        <summary>${title}</summary>
        <textarea id="input-${key}" spellcheck="false" placeholder="${escapeHtml(inputPlaceholder(key))}">${escapeHtml(formatJson(inputs[key] || {}))}</textarea>
      </details>
    `)
    .join("")}
      </div>
    </details>
  `;
  bindInputReadiness();
  updateIntakeChecklist();
}

function renderEmptyWorkspace() {
  renderInputDrawers({});
  byId("authorityRef").textContent = "none loaded";
  byId("outcomeRef").textContent = "not emitted";
  byId("requestRef").textContent = "no execution";
  byId("targetRef").textContent = "awaiting SDK run or artifact";
  byId("latencyRef").textContent = "not evaluated";
  byId("kernelRef").textContent = "CRI-CORE";
  byId("executionTitle").textContent = "Evaluation inspector";
  byId("decisionState").textContent = "WAITING";
  byId("decisionState").className = "status-pill waiting";
  byId("primaryAnswer").textContent = "Open a Guard SDK run or load an evaluation artifact.";
  byId("whyList").innerHTML = `<div class="short-item muted">no evaluation yet</div>`;
  byId("nextList").innerHTML = `<div class="short-item muted">load a saved run, upload an artifact, or use an example input set</div>`;
  byId("postureRail").innerHTML = "";
  byId("traceHash").textContent = "not evaluated";
  byId("traceSurface").innerHTML = "";
  byId("chronologyList").innerHTML = "";
  byId("telemetryStream").innerHTML = "";
  renderReceipt(null);
  byId("exampleLabel").textContent = "Artifact Intake";
}

function readInputDrawers() {
  return Object.fromEntries(
    inputConfig.map(([key]) => [key, JSON.parse(byId(`input-${key}`).value)])
  );
}

function readInputDrawer(key) {
  const input = byId(`input-${key}`);
  if (!input) return null;
  try {
    return JSON.parse(input.value || "{}");
  } catch {
    return null;
  }
}

function inputPlaceholder(key) {
  const placeholders = {
    compiled_authority: "Paste compiled_authority_contract.v1 JSON here.",
    execution_request: "Paste normalized_execution_request.v1 JSON here.",
    runtime_evidence: "Paste guard_runtime_evidence_model.v1 JSON here.",
    continuity_posture: "Paste optional continuity posture JSON here, or leave as {}."
  };
  return placeholders[key] || "Paste JSON here.";
}

function requiredInputsPresent() {
  return inputReady("compiled_authority", "compiled_authority_contract.v1")
    && inputReady("execution_request", "normalized_execution_request.v1")
    && inputReady("runtime_evidence", "guard_runtime_evidence_model.v1");
}

function inputReady(key, schemaVersion) {
  const payload = readInputDrawer(key);
  return Boolean(payload && payload.schema_version === schemaVersion);
}

function continuityLoaded() {
  const posture = readInputDrawer("continuity_posture");
  return Boolean(posture && Object.keys(posture).length > 0);
}

function bindInputReadiness() {
  inputConfig.forEach(([key]) => {
    const input = byId(`input-${key}`);
    if (input) {
      input.addEventListener("input", updateIntakeChecklist);
    }
  });
}

function updateIntakeChecklist() {
  const items = [
    {
      label: "Compiled authority loaded",
      state: inputReady("compiled_authority", "compiled_authority_contract.v1") ? "ok" : "missing"
    },
    {
      label: "Execution request loaded",
      state: inputReady("execution_request", "normalized_execution_request.v1") ? "ok" : "missing"
    },
    {
      label: "Runtime evidence loaded",
      state: inputReady("runtime_evidence", "guard_runtime_evidence_model.v1") ? "ok" : "missing"
    },
    {
      label: "Continuity posture optional",
      state: continuityLoaded() ? "ok" : "optional"
    }
  ];
  byId("intakeChecklist").innerHTML = items.map((item) => `
    <span class="check-item ${item.state}">
      <span class="check-dot" aria-hidden="true"></span>
      ${escapeHtml(item.label)}
    </span>
  `).join("");
  byId("evaluateButton").disabled = !requiredInputsPresent();
}

function renderEvaluation(payload) {
  const evaluation = payload.evaluation;
  const outcome = payload.guard_enforcement_outcome;
  const inputs = payload.inputs;
  const request = inputs.execution_request;
  const evidence = inputs.runtime_evidence;
  const authorityRef = outcome.authority_ref;
  const latency = evidence.execution_context?.latency_ms ?? "runtime";
  const status = outcome.status;

  byId("authorityRef").textContent = authorityRef;
  byId("outcomeRef").textContent = outcome.schema_version || outcomeContractSchema;
  byId("requestRef").textContent = request.request_id;
  byId("targetRef").textContent = `${request.action} -> ${request.target}`;
  byId("latencyRef").textContent = typeof latency === "number" ? `${latency} ms` : String(latency);
  byId("kernelRef").textContent = "CRI-CORE";
  byId("executionTitle").textContent = `Execution #${request.request_id}`;
  byId("decisionState").textContent = postureValue(status).toUpperCase();
  byId("decisionState").className = `status-pill ${toneForStatus(status)}`;
  byId("primaryAnswer").textContent = primaryAnswer(status);
  byId("traceHash").textContent = evaluation.evaluation_trace.trace_hash;

  renderPosture(evaluation);
  renderDecisionLists(evaluation);
  renderTrace(evaluation);
  renderChronology(payload.chronology || []);
  renderTelemetry(payload.evaluation_events || evaluation.telemetry_events || []);
}

function renderHistory(evaluations) {
  const filtered = filterHistory(evaluations);
  byId("historyList").innerHTML = filtered.length
    ? filtered.map((item) => `
        <button type="button" class="history-row" data-run-id="${escapeHtml(item.run_id)}">
          <span class="history-status ${toneForStatus(item.status)}">${escapeHtml(postureValue(item.status).toUpperCase())}</span>
          <strong>${escapeHtml(item.request_id || item.run_id)}</strong>
          <span>${escapeHtml(item.action || "execution")} -> ${escapeHtml(item.target || "runtime")}</span>
          <small>${escapeHtml(item.authority_ref || "unknown authority")} | ${escapeHtml(item.rationale)}</small>
        </button>
      `).join("")
    : `<div class="empty-record">${evaluations.length ? "No evaluations match the current filter." : "No saved evaluations yet."}</div>`;
  document.querySelectorAll("[data-run-id]").forEach((item) => {
    item.addEventListener("click", async () => {
      try {
        await loadSavedRun(item.dataset.runId);
      } catch (error) {
        setStatus(error.message);
      }
    });
  });
}

function filterHistory(evaluations) {
  const query = state.historySearch.trim().toLowerCase();
  return evaluations.filter((item) => {
    if (state.historyFilter !== "all" && item.status !== state.historyFilter) return false;
    if (!query) return true;
    return [
      item.run_id,
      item.request_id,
      item.action,
      item.target,
      item.authority_ref,
      item.rationale,
      item.receipt?.receipt_hash
    ].some((value) => String(value || "").toLowerCase().includes(query));
  });
}

function renderReceipt(receipt) {
  if (!receipt || !receipt.schema_version) {
    byId("receiptTitle").textContent = "No receipt selected";
    byId("receiptBrowser").innerHTML = `
      <div class="lineage-empty">Save or select a run to inspect its governance lineage.</div>
    `;
    return;
  }
  const latest = state.latest || {};
  const inputs = latest.inputs || {};
  const evaluation = latest.evaluation || {};
  const authority = inputs.compiled_authority || {};
  const evidence = inputs.runtime_evidence || {};
  const request = inputs.execution_request || {};
  const continuity = inputs.continuity_posture || evidence.continuity_snapshot || {};
  const replay = evidence.replay_evidence || {};
  byId("receiptTitle").textContent = receipt.run_id || "Receipt";
  byId("receiptBrowser").innerHTML = `
    <div class="lineage-path" aria-label="Evaluation lineage">
      <span>Guard SDK</span>
      <span>CRI-CORE evaluation</span>
      <span>Guard receipt</span>
    </div>
    <dl class="receipt-fields lineage-fields">
      <div><dt>Decision</dt><dd>${escapeHtml(postureValue(receipt.outcome_status || "blocked"))}</dd></div>
      <div><dt>Authority</dt><dd>${escapeHtml(receipt.authority_ref || "unknown")}</dd></div>
      <div><dt>Contract hash</dt><dd>${escapeHtml(authority.contract_hash || "not available")}</dd></div>
      <div><dt>Actor</dt><dd>${escapeHtml(actorSummary(evidence.actor_identity))}</dd></div>
      <div><dt>Evidence</dt><dd>${escapeHtml(evidenceSummaryLine(evidence))}</dd></div>
      <div><dt>Replay</dt><dd>${escapeHtml(replaySummaryLine(replay, evaluation))}</dd></div>
      <div><dt>Continuity</dt><dd>${escapeHtml(continuitySummaryLine(continuity, evaluation))}</dd></div>
      <div><dt>Mutation domain</dt><dd>${escapeHtml(`${request.action || "execution"} -> ${request.target || "runtime"}`)}</dd></div>
      <div><dt>Trace hash</dt><dd>${escapeHtml(receipt.evaluation_trace_hash || "")}</dd></div>
      <div><dt>Outcome hash</dt><dd>${escapeHtml(receipt.outcome_hash || "")}</dd></div>
      <div><dt>Receipt hash</dt><dd>${escapeHtml(receipt.receipt_hash || "")}</dd></div>
      <div><dt>Events</dt><dd>${escapeHtml(String((receipt.chronology_event_ids || []).length))}</dd></div>
    </dl>
  `;
}

function actorSummary(actor) {
  if (!actor) return "not available";
  return [actor.id, actor.role, actor.type].filter(Boolean).join(" | ") || "not available";
}

function evidenceSummaryLine(evidence) {
  const approvals = evidence.approvals || [];
  if (!approvals.length) return "no approvals attached";
  return `${approvals.length} approval${approvals.length === 1 ? "" : "s"} attached`;
}

function replaySummaryLine(replay, evaluation) {
  const obligations = evaluation.replay_obligations || [];
  if (obligations.length) return `${obligations.length} replay obligation${obligations.length === 1 ? "" : "s"}`;
  if (replay.required) return "replay required";
  return "replay satisfied or not required";
}

function continuitySummaryLine(continuity, evaluation) {
  const requirements = evaluation.continuity_requirements || [];
  if (requirements.length) return `${requirements.length} continuity requirement${requirements.length === 1 ? "" : "s"}`;
  if (continuity.requires_revalidation) return "revalidation required";
  return "stable";
}

function receiptForRun(runId) {
  return (state.history.find((item) => item.run_id === runId) || {}).receipt || null;
}

function renderDecisionLists(evaluation) {
  byId("whyList").innerHTML = shortWhy(evaluation)
    .map((item) => `<div class="short-item">${item}</div>`)
    .join("");
  byId("nextList").innerHTML = shortNextActions(evaluation)
    .map((item) => `<div class="short-item">${item}</div>`)
    .join("");
}

function renderPosture(evaluation) {
  const chips = [
    ["Admissibility", postureValue(evaluation.status), toneForStatus(evaluation.status)],
    ["Continuity", evaluation.continuity_requirements.length ? "Drift Detected" : "Stable", evaluation.continuity_requirements.length ? "warn" : "ok"],
    ["Replay", evaluation.replay_obligations.length ? "Incomplete" : "Linked", evaluation.replay_obligations.length ? "warn" : "ok"],
    ["Evidence", evaluation.required_evidence.length ? "Missing Evidence" : "Satisfied", evaluation.required_evidence.length ? "blocked" : "ok"],
    ["Enforcement", enforcementValue(evaluation.status), toneForStatus(evaluation.status)]
  ];
  byId("postureRail").innerHTML = chips
    .map(([label, value, tone]) => `
      <div class="posture-chip ${tone}">
        <span>${label}</span>
        <strong>${value}</strong>
      </div>
    `)
    .join("");
}

function renderOutputs(evaluation) {
  const outputs = [
    ["Violated constraints", evaluation.violated_constraints, "critical"],
    ["Missing evidence", evaluation.required_evidence, "critical"],
    ["Replay obligations", evaluation.replay_obligations, ""],
    ["Continuity failures", evaluation.continuity_requirements, ""]
  ];
  byId("outputGrid").innerHTML = outputs
    .map(([title, rows, tone]) => `
      <article class="cognition-card ${tone}">
        <h3>${title}</h3>
        <div class="data-list">
          ${renderRows(rows)}
        </div>
      </article>
    `)
    .join("");
}

function renderTrace(evaluation) {
  const cards = [
    {
      kicker: "Decision basis",
      title: postureValue(evaluation.status),
      summary: primaryAnswer(evaluation.status),
      details: shortWhy(evaluation).join("; ")
    },
    {
      kicker: "Failed constraint",
      title: evaluation.violated_constraints.length ? "Constraint failed" : "No failed constraint",
      summary: firstOrNone(evaluation.violated_constraints, constraintSummary),
      details: evaluation.violated_constraints
    },
    {
      kicker: "Evidence",
      title: evaluation.required_evidence.length ? "Evidence missing" : "Evidence satisfied",
      summary: firstOrNone(evaluation.required_evidence, evidenceSummary),
      details: evaluation.required_evidence
    },
    {
      kicker: "Continuity",
      title: evaluation.continuity_requirements.length ? "Revalidation required" : "Continuity stable",
      summary: firstOrNone(evaluation.continuity_requirements, continuitySummary),
      details: evaluation.continuity_requirements
    },
    {
      kicker: "Replay",
      title: evaluation.replay_obligations.length ? "Replay required" : "Replay linked",
      summary: firstOrNone(evaluation.replay_obligations, replaySummary),
      details: evaluation.replay_obligations
    }
  ];
  byId("traceSurface").innerHTML = cards
    .map((card) => `
      <article class="trace-item">
        <span>${escapeHtml(card.kicker)}</span>
        <strong>${escapeHtml(card.title)}</strong>
        <p>${escapeHtml(card.summary)}</p>
        ${technicalDetails(card.details)}
      </article>
    `)
    .join("");
}

function renderChronology(events) {
  byId("chronologyList").innerHTML = events
    .map((event) => `
      <li data-kind="${chronologyKind(event.event_type)}">
        <span class="sequence">${String(event.sequence).padStart(2, "0")}</span>
        <div>
          <strong class="event-name">${escapeHtml(eventTitle(event))}</strong>
          <p class="event-detail">${escapeHtml(eventSummary(event))}</p>
          ${technicalDetails(event)}
        </div>
        <span class="event-link">${escapeHtml(eventBadge(event.event_type))}</span>
      </li>
    `)
    .join("");
  applyChronologyFilter(
    localStorage.getItem(storageKeys.filter)
      || document.querySelector("[data-filter].active")?.dataset.filter
      || "all",
    { persist: false }
  );
}

function renderTelemetry(events) {
  const latest = [...events].sort((a, b) => b.sequence - a.sequence).slice(0, 40);
  byId("telemetryStream").innerHTML = latest
    .map((event) => `
      <article class="telemetry-event">
        <strong>${escapeHtml(eventTitle(event))}</strong>
        <p>${escapeHtml(eventSummary(event))}</p>
        <span>${escapeHtml(event.timestamp)}</span>
        ${technicalDetails(event)}
      </article>
    `)
    .join("");
}

function renderRows(rows) {
  if (!rows.length) {
    return `<div class="data-row"><span class="dot"></span><span>none</span></div>`;
  }
  return rows
    .map((row) => `
      <div class="data-row">
        <span class="dot"></span>
        <span>${summarize(row)}</span>
      </div>
    `)
    .join("");
}

function firstOrNone(rows, formatter) {
  return rows.length ? formatter(rows[0]) : "No action required.";
}

function conditionText(condition) {
  if (!condition) return "";
  return `${condition.field} ${condition.operator} ${condition.value}`;
}

function constraintSummary(constraint) {
  if (constraint.constraint === "required_role") {
    const required = (constraint.required_roles || []).join(" or ");
    return `Actor role ${constraint.observed_role} is not authorized; ${required} required.`;
  }
  return sentence(constraint.rationale || summarize(constraint));
}

function evidenceSummary(evidence) {
  if (evidence.evidence === "approval" && evidence.role) {
    const condition = conditionText(evidence.condition);
    return condition
      ? `${capitalize(evidence.role)} approval missing for ${condition}.`
      : `${capitalize(evidence.role)} approval missing.`;
  }
  return sentence(evidence.rationale || summarize(evidence));
}

function continuitySummary(requirement) {
  if (requirement.requirement === "revalidation") {
    return "Continuity revalidation required before execution can proceed.";
  }
  return sentence(requirement.rationale || summarize(requirement));
}

function replaySummary(obligation) {
  if (obligation.obligation === "link_replay") {
    return "Replay evidence must be linked before enforcement.";
  }
  return sentence(obligation.rationale || summarize(obligation));
}

function eventTitle(event) {
  const labels = {
    authority_context_resolved: "Compiled authority loaded",
    evaluation_pipeline_started: "Evaluation started",
    runtime_evidence_loaded: "Runtime evidence loaded",
    continuity_checked: "Continuity checked",
    replay_validated: "Replay checked",
    admissibility_evaluated: "Admissibility evaluated",
    enforcement_outcome_recorded: "Enforcement outcome emitted"
  };
  return labels[event.event_type] || humanize(event.event_type);
}

function eventSummary(event) {
  const details = event.details || {};
  if (event.event_type === "authority_context_resolved") {
    return "Compiled authority accepted as the governance boundary.";
  }
  if (event.event_type === "evaluation_pipeline_started") {
    return "Guard began evaluating this execution request.";
  }
  if (event.event_type === "runtime_evidence_loaded") {
    return details.required_evidence?.length
      ? evidenceSummary(details.required_evidence[0])
      : "Runtime evidence model loaded.";
  }
  if (event.event_type === "continuity_checked") {
    return details.continuity_requirements?.length
      ? continuitySummary(details.continuity_requirements[0])
      : "Continuity is stable.";
  }
  if (event.event_type === "replay_validated") {
    return details.replay_obligations?.length
      ? replaySummary(details.replay_obligations[0])
      : "Replay evidence is linked.";
  }
  if (event.event_type === "admissibility_evaluated") {
    if (details.violated_constraints?.length) return constraintSummary(details.violated_constraints[0]);
    if (details.required_evidence?.length) return evidenceSummary(details.required_evidence[0]);
    return `Execution evaluated as ${details.status || "admissible"}.`;
  }
  if (event.event_type === "enforcement_outcome_recorded") {
    const consequence = details.consequences?.[0]?.consequence || details.status;
    if (consequence === "block_execution") return "Execution stopped at the Guard boundary.";
    if (consequence === "allow_execution") return "Execution may proceed.";
    if (consequence === "escalate_execution") return "Execution held for escalation.";
  }
  return summarize(details) || "Evaluation event generated.";
}

function eventBadge(eventType) {
  const kind = chronologyKind(eventType);
  return kind === "all" ? "evaluation" : kind;
}

function technicalDetails(value) {
  if (!value || (Array.isArray(value) && !value.length)) return "";
  return `
    <details class="technical-detail">
      <summary>Technical detail</summary>
      <pre>${escapeHtml(formatJson(value))}</pre>
    </details>
  `;
}

function sentence(text) {
  if (!text) return "No action required.";
  return text.endsWith(".") ? text : `${text}.`;
}

function capitalize(text) {
  if (!text) return "";
  return `${text[0].toUpperCase()}${text.slice(1)}`;
}

function humanize(text) {
  return capitalize(String(text).replaceAll("_", " "));
}

function shortWhy(evaluation) {
  const items = [];
  if (evaluation.violated_constraints.length) {
    items.push("failed constraint");
  }
  if (evaluation.required_evidence.length) {
    items.push("missing evidence");
  }
  if (evaluation.continuity_requirements.length) {
    items.push("continuity drift");
  }
  if (evaluation.replay_obligations.length) {
    items.push("replay mismatch");
  }
  return items.length ? items : ["requirements satisfied"];
}

function shortNextActions(evaluation) {
  const actions = [];
  for (const evidence of evaluation.required_evidence || []) {
    if (evidence.role) {
      actions.push(`obtain ${evidence.role} approval`);
    } else {
      actions.push("attach required evidence");
    }
  }
  if (evaluation.replay_obligations.length) {
    actions.push("attach replay evidence");
  }
  if (evaluation.continuity_requirements.length) {
    actions.push("revalidate continuity");
  }
  if (evaluation.status !== "admissible") {
    actions.push("retry execution");
  }
  return actions.length ? [...new Set(actions)] : ["proceed with execution"];
}

function applyChronologyFilter(filter, options = {}) {
  if (options.persist !== false) {
    localStorage.setItem(storageKeys.filter, filter);
  }
  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.classList.toggle("active", button.dataset.filter === filter);
  });
  document.querySelectorAll(".chronology-list li").forEach((item) => {
    item.hidden = filter !== "all" && item.dataset.kind !== filter;
  });
}

function chronologyKind(eventType) {
  if (eventType.includes("evidence")) return "evidence";
  if (eventType.includes("replay")) return "replay";
  if (eventType.includes("continuity")) return "continuity";
  return "all";
}

function postureValue(status) {
  if (status === "admissible") return "Allowed";
  if (status === "escalated") return "Escalated";
  return "Blocked";
}

function decisionAnswer(status) {
  if (status === "admissible") return "YES";
  if (status === "escalated") return "ESCALATE";
  return "NO";
}

function enforcementValue(status) {
  if (status === "admissible") return "Proceed";
  if (status === "escalated") return "Escalation Required";
  return "Stopped";
}

function toneForStatus(status) {
  if (status === "admissible") return "ok";
  if (status === "escalated") return "warn";
  return "blocked";
}

function primaryAnswer(status) {
  if (status === "admissible") return "Yes. This execution may proceed.";
  if (status === "escalated") return "Not yet. This execution requires escalation.";
  return "No. This execution cannot proceed.";
}

function consequenceText(outcome) {
  const consequence = outcome.consequences?.[0]?.consequence;
  if (consequence === "allow_execution") return "Execution authorized at boundary";
  if (consequence === "escalate_execution") return "Execution held for escalation";
  return "Execution stopped at boundary";
}

function nextActionText(evaluation) {
  const requirements = []
    .concat(evaluation.required_evidence || [])
    .concat(evaluation.replay_obligations || [])
    .concat(evaluation.continuity_requirements || []);
  if (!requirements.length) return "No blockers remain for this execution.";
  return requirements.map(summarize).join("; ");
}

function tightRationale(rationale) {
  if (!rationale) return "Runtime evaluation completed.";
  return rationale.endsWith(".") ? rationale : `${rationale}.`;
}

function setStatus(message) {
  byId("ingestStatus").textContent = message;
}

function clearInputs() {
  for (const [key] of inputConfig) {
    const input = byId(`input-${key}`);
    if (input) input.value = "{}";
  }
  state.latest = null;
  state.savedRunId = null;
  byId("runRef").textContent = "no saved run";
  byId("exampleLabel").textContent = "Artifact Intake";
  hideIntakeHelper();
  updateIntakeChecklist();
  setStatus("Inputs cleared");
}

function focusExecutionRequestInput() {
  const input = byId("input-execution_request");
  if (!input) return;
  const advanced = input.closest(".advanced-json");
  if (advanced) advanced.open = true;
  input.closest("details").open = true;
  showIntakeHelper("Paste a normalized_execution_request.v1 JSON object below. Guard does not normalize raw request text in this surface.");
  input.focus();
  setStatus("Edit normalized_execution_request.v1 in the request input");
}

function showIntakeHelper(message) {
  const helper = byId("intakeHelper");
  helper.textContent = message;
  helper.hidden = false;
}

function hideIntakeHelper() {
  const helper = byId("intakeHelper");
  helper.textContent = "";
  helper.hidden = true;
}

async function uploadEvaluationArtifact(file) {
  if (!file) return;
  const artifact = JSON.parse(await file.text());
  if (artifact.evaluation && artifact.inputs) {
    state.latest = artifact;
    renderInputDrawers(artifact.inputs);
    renderEvaluation(artifact);
    setStatus("Loaded evaluation artifact");
    return;
  }
  if (artifact.receipt && artifact.inputs && artifact.evaluation) {
    state.latest = artifact;
    renderInputDrawers(artifact.inputs);
    renderEvaluation(artifact);
    setStatus("Loaded saved evaluation artifact");
    return;
  }
  renderInputDrawers(artifact);
  state.latest = null;
  setStatus("Loaded execution input artifact. Evaluate when ready.");
}

function downloadJson(payload, filename) {
  const blob = new Blob([`${formatJson(payload)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function exportHistory() {
  const filtered = filterHistory(state.history);
  downloadJson(
    {
      schema_version: "guard_evaluation_history_export.v1",
      exported_count: filtered.length,
      evaluations: filtered
    },
    "guard-evaluation-history.json"
  );
  setStatus(`Exported ${filtered.length} evaluation history record${filtered.length === 1 ? "" : "s"}`);
}

document.querySelectorAll("[data-filter]").forEach((button) => {
  button.addEventListener("click", () => applyChronologyFilter(button.dataset.filter));
});

document.querySelectorAll("[data-tab]").forEach((button) => {
  button.addEventListener("click", () => {
    activateTab(button.dataset.tab);
  });
});

function activateTab(selected) {
  selected = tabAliases[selected] || selected || "decision";
  if (!document.getElementById(selected)) {
    selected = "decision";
  }
  const activePanel = document.querySelector(".tab-panel.active");
  if (activePanel) {
    scrollState[activePanel.id] = window.scrollY;
    sessionStorage.setItem(storageKeys.scroll, JSON.stringify(scrollState));
  }
  localStorage.setItem(storageKeys.tab, selected);
  document.querySelectorAll("[data-tab]").forEach((item) => {
    item.classList.toggle("active", item.dataset.tab === selected);
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === selected);
  });
  requestAnimationFrame(() => {
    window.scrollTo({ top: scrollState[selected] || 0, behavior: "instant" });
  });
}

byId("evaluateButton").addEventListener("click", async () => {
  try {
    await evaluateCurrentInputs();
  } catch (error) {
    setStatus(error.message);
  }
});

byId("loadSampleButton").addEventListener("click", async () => {
  try {
    hideIntakeHelper();
    await loadSampleInputs();
  } catch (error) {
    setStatus(error.message);
  }
});

byId("pasteRequestButton").addEventListener("click", focusExecutionRequestInput);

byId("uploadArtifactButton").addEventListener("click", () => {
  byId("artifactInput").click();
});

byId("loadSavedRunButton").addEventListener("click", async () => {
  try {
    await loadMostRecentRun();
  } catch (error) {
    setStatus(error.message);
  }
});

byId("connectWorkspaceButton").addEventListener("click", async () => {
  try {
    await refreshHistory();
    setStatus("Refreshed local .guard-local evaluation history");
  } catch (error) {
    setStatus(error.message);
  }
});

byId("exportHistoryButton").addEventListener("click", exportHistory);

byId("historySearch").addEventListener("input", (event) => {
  state.historySearch = event.target.value;
  renderHistory(state.history);
});

byId("historyFilter").addEventListener("change", (event) => {
  state.historyFilter = event.target.value;
  renderHistory(state.history);
});

byId("artifactInput").addEventListener("change", async (event) => {
  try {
    await uploadEvaluationArtifact(event.target.files[0]);
    event.target.value = "";
  } catch (error) {
    setStatus(error.message);
  }
});

byId("clearInputsButton").addEventListener("click", clearInputs);

byId("saveRunButton").addEventListener("click", async () => {
  try {
    await saveCurrentRun();
  } catch (error) {
    setStatus(error.message);
  }
});

byId("replayRunButton").addEventListener("click", async () => {
  try {
    await replaySavedRun();
  } catch (error) {
    setStatus(error.message);
  }
});

byId("exportReceiptButton").addEventListener("click", async () => {
  try {
    await exportCurrentReceipt();
  } catch (error) {
    setStatus(error.message);
  }
});

(async function start() {
  try {
    activateTab(localStorage.getItem(storageKeys.tab) || "decision");
    renderEmptyWorkspace();
    await refreshHistory();
    applyChronologyFilter(localStorage.getItem(storageKeys.filter) || "all");
  } catch (error) {
    setStatus(`Local runtime API unavailable: ${error.message}`);
  }
})();
