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
const scrollState = JSON.parse(sessionStorage.getItem(storageKeys.scroll) || "{}");

const byId = (id) => document.getElementById(id);
const formatJson = (value) => JSON.stringify(value, null, 2);

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

async function pollTelemetry() {
  try {
    const response = await fetch("/api/runtime/telemetry", { cache: "no-store" });
    if (!response.ok) return;
    const body = await response.json();
    renderTelemetry(body.telemetry_stream || []);
  } catch {
    // The local server may not be running yet. The main status surface already reports this.
  }
}

function renderInputDrawers(inputs) {
  byId("payloadDrawers").innerHTML = inputConfig
    .map(([key, title]) => `
      <details>
        <summary>${title}</summary>
        <textarea id="input-${key}" spellcheck="false">${formatJson(inputs[key])}</textarea>
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
  renderTelemetry(payload.telemetry_stream || []);
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
  const trace = evaluation.evaluation_trace;
  const traceRows = [
    ["evaluated constraints", evaluation.admissibility_projection.violated_constraints.concat(evaluation.required_evidence)],
    ["satisfied requirements", trace.steps.filter((step) => step.status === "completed")],
    ["failed requirements", evaluation.violated_constraints.concat(evaluation.required_evidence)],
    ["escalation triggers", evaluation.continuity_requirements],
    ["replay dependencies", evaluation.replay_obligations]
  ];
  byId("traceSurface").innerHTML = traceRows
    .map(([title, rows]) => `
      <article class="trace-item">
        <strong>${title}</strong>
        <p>${rows.length ? rows.map(summarize).join("; ") : "none"}</p>
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
          <strong class="event-name">${event.event_type}</strong>
          <p class="event-detail">${summarize(event.details)}</p>
        </div>
        <span class="event-link">${chronologyKind(event.event_type)}-linked</span>
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
        <strong>${event.event_type}</strong>
        <p>${summarize(event.details)}</p>
        <span>${event.timestamp}</span>
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
    await pollTelemetry();
  } catch (error) {
    setStatus(error.message);
  }
});

(async function start() {
  try {
    activateTab(localStorage.getItem(storageKeys.tab) || "decision");
    await loadRuntimeInputs();
    await evaluateCurrentInputs();
    await pollTelemetry();
    applyChronologyFilter(localStorage.getItem(storageKeys.filter) || "all");
    setInterval(pollTelemetry, 3000);
  } catch (error) {
    setStatus(`Local runtime API unavailable: ${error.message}`);
  }
})();
