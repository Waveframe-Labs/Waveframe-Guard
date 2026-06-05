const state = {
  inputs: null,
  latest: null
};

const inputConfig = [
  ["compiled_authority", "View compiled authority"],
  ["execution_request", "View normalized request"],
  ["runtime_evidence", "View runtime evidence"]
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

async function loadRuntimeInputs() {
  setStatus("Loading runtime inputs");
  const response = await fetch("/api/runtime/inputs", { cache: "no-store" });
  if (!response.ok) throw new Error(`Input load failed: ${response.status}`);
  state.inputs = await response.json();
  renderInputDrawers(state.inputs);
  setStatus("Runtime inputs loaded");
}

async function evaluateCurrentInputs() {
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

function renderInputDrawers(inputs) {
  byId("payloadDrawers").innerHTML = inputConfig
    .map(([key, title]) => `
      <details>
        <summary>${title}</summary>
        <textarea id="input-${key}" spellcheck="false">${escapeHtml(formatJson(inputs[key]))}</textarea>
      </details>
    `)
    .join("");
}

function readInputDrawers() {
  return Object.fromEntries(
    inputConfig.map(([key]) => [key, JSON.parse(byId(`input-${key}`).value)])
  );
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
  byId("decisionState").textContent = decisionAnswer(status);
  byId("primaryAnswer").textContent = primaryAnswer(status);
  byId("traceHash").textContent = evaluation.evaluation_trace.trace_hash;

  renderPosture(evaluation);
  renderDecisionLists(evaluation);
  renderTrace(evaluation);
  renderChronology(payload.chronology || []);
  renderTelemetry(payload.telemetry_appended || evaluation.telemetry_events || []);
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

(async function start() {
  try {
    activateTab(localStorage.getItem(storageKeys.tab) || "decision");
    await loadRuntimeInputs();
    await evaluateCurrentInputs();
    applyChronologyFilter(localStorage.getItem(storageKeys.filter) || "all");
  } catch (error) {
    setStatus(`Local runtime API unavailable: ${error.message}`);
  }
})();
