const runtimeEvaluation = {
  authority: {
    schema_version: "compiled_authority_contract.v1",
    contract_id: "finance-policy",
    contract_version: "1.0.0",
    contract_hash: "sha256:contract",
    authority_requirements: { required_roles: ["manager"] },
    approval_requirements: {
      required: [
        { role: "manager" },
        { role: "director", condition: { field: "amount", operator: ">", value: 10000 } }
      ]
    },
    artifact_requirements: {},
    stage_requirements: {},
    invariants: { separation_of_duties: true }
  },
  request: {
    schema_version: "normalized_execution_request.v1",
    request_id: "exec-1",
    action: "transfer",
    target: "wire",
    arguments: { amount: 12500 },
    artifacts: []
  },
  evidence: {
    schema_version: "guard_runtime_evidence_model.v1",
    actor_identity: { id: "employee-1", type: "human", role: "employee" },
    approvals: [{ role: "manager", approved_by: "manager-1" }],
    replay_evidence: { required: true, replay_id: null },
    continuity_snapshot: {
      requires_revalidation: true,
      signals: ["AUTHORITY_SUPERSEDED_DURING_EXECUTION"]
    },
    timestamp_source: {
      source: "caller_supplied",
      timestamp: "2026-06-03T22:30:00+00:00"
    },
    execution_context: { surface: "sdk", environment: "local", latency_ms: 14 }
  },
  continuity: {
    schema_version: "guard_continuity_posture.v1",
    authority_ref: "finance-policy@1.0.0",
    requires_revalidation: true,
    requires_replay: true,
    signals: ["AUTHORITY_SUPERSEDED_DURING_EXECUTION"],
    continuity_requirements: [
      {
        requirement: "revalidation",
        rationale: "authority drift detected during runtime continuity check"
      }
    ],
    replay_obligations: [
      {
        obligation: "link_replay",
        rationale: "execution must be linked to replay before enforcement"
      }
    ]
  },
  result: {
    status: "blocked",
    answer: "No. This execution cannot proceed.",
    rationale: "Actor role is not authorized by compiled authority.",
    consequence: "Execution stopped at boundary",
    next: "Director approval, replay link, and continuity revalidation are required before retry.",
    violated_constraints: [
      {
        constraint: "required_role",
        required_roles: ["manager"],
        observed_role: "employee",
        rationale: "actor role is not authorized by compiled authority"
      }
    ],
    required_evidence: [
      {
        evidence: "approval",
        role: "director",
        condition: { field: "amount", operator: ">", value: 10000 },
        rationale: "required approval evidence is missing"
      }
    ],
    replay_obligations: [
      {
        obligation: "link_replay",
        rationale: "execution must be linked to replay before enforcement"
      }
    ],
    continuity_requirements: [
      {
        requirement: "revalidation",
        rationale: "authority drift detected during runtime continuity check"
      }
    ],
    enforcement_outcome: {
      schema_version: "guard_enforcement_outcome.v1",
      authority_ref: "finance-policy@1.0.0",
      status: "blocked",
      rationale: "actor role is not authorized by compiled authority",
      consequences: [{ consequence: "block_execution" }],
      outcome_id: "enforcement_outcome_d7a9e5e1124f",
      outcome_hash: "sha256:outcome"
    }
  },
  chronology: [
    ["01", "evaluation_started", "Runtime boundary opened for execution request", "all", "trace"],
    ["02", "evidence_loaded", "Actor identity, approvals, replay evidence, continuity snapshot, timestamp source, and execution context loaded", "evidence", "evidence"],
    ["03", "continuity_checked", "Authority supersession signal requires revalidation", "continuity", "continuity"],
    ["04", "replay_validated", "Replay evidence is incomplete for this execution", "replay", "replay"],
    ["05", "admissibility_evaluated", "Required role constraint failed and director approval is missing", "all", "trace"],
    ["06", "enforcement_emitted", "guard_enforcement_outcome.v1 emitted with block consequence", "all", "outcome"]
  ],
  trace: {
    trace_hash: "sha256:trace",
    evaluated_constraints: [
      "required_role expected manager, observed employee",
      "approval requirement evaluated for amount > 10000"
    ],
    satisfied_requirements: [
      "compiled_authority_contract.v1 accepted",
      "normalized_execution_request.v1 accepted",
      "manager approval evidence present"
    ],
    failed_requirements: [
      "actor role is not authorized by compiled authority",
      "director approval missing for amount > 10000"
    ],
    escalation_triggers: [
      "continuity revalidation required",
      "replay linkage incomplete"
    ],
    replay_dependencies: [
      "link_replay before retrying execution"
    ]
  },
  telemetry: [
    ["22:30:00.014", "block", "required_role constraint failed"],
    ["22:30:00.013", "evidence_failure", "director approval missing"],
    ["22:30:00.012", "continuity_failure", "authority supersession drift detected"],
    ["22:30:00.011", "replay_mismatch", "replay evidence incomplete"],
    ["22:30:00.010", "escalate", "revalidation and replay linkage required"]
  ]
};

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

const payloads = [
  ["View compiled authority", runtimeEvaluation.authority],
  ["View normalized request", runtimeEvaluation.request],
  ["View runtime evidence", runtimeEvaluation.evidence],
  ["View continuity posture", runtimeEvaluation.continuity]
];

document.getElementById("payloadDrawers").innerHTML = payloads
  .map(([title, payload]) => `
    <details>
      <summary>${title}</summary>
      <pre>${formatJson(payload)}</pre>
    </details>
  `)
  .join("");

const outputs = [
  ["Violated constraints", runtimeEvaluation.result.violated_constraints, "critical"],
  ["Missing evidence", runtimeEvaluation.result.required_evidence, "critical"],
  ["Replay obligations", runtimeEvaluation.result.replay_obligations, ""],
  ["Continuity failures", runtimeEvaluation.result.continuity_requirements, ""]
];

document.getElementById("outputGrid").innerHTML = outputs
  .map(([title, rows, tone]) => `
    <article class="cognition-card ${tone}">
      <h3>${title}</h3>
      <div class="data-list">
        ${rows.map((row) => `
          <div class="data-row">
            <span class="dot"></span>
            <span>${summarize(row)}</span>
          </div>
        `).join("")}
      </div>
    </article>
  `)
  .join("");

const postureChips = [
  ["Admissibility", "Blocked", "blocked"],
  ["Continuity", "Drift Detected", "warn"],
  ["Replay", "Incomplete", "warn"],
  ["Evidence", "Missing Approval", "blocked"],
  ["Enforcement", "Escalation Required", "warn"]
];

document.getElementById("postureRail").innerHTML = postureChips
  .map(([label, value, state]) => `
    <div class="posture-chip ${state}">
      <span>${label}</span>
      <strong>${value}</strong>
    </div>
  `)
  .join("");

const renderChronology = (filter = "all") => {
  const events = runtimeEvaluation.chronology.filter(([, , , group]) => filter === "all" || group === filter);
  document.getElementById("chronologyList").innerHTML = events
    .map(([sequence, event, detail, , link]) => `
      <li>
        <span class="sequence">${sequence}</span>
        <div>
          <strong class="event-name">${event}</strong>
          <p class="event-detail">${detail}</p>
        </div>
        <span class="event-link">${link}-linked</span>
      </li>
    `)
    .join("");
};

document.querySelectorAll("[data-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll("[data-filter]").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    renderChronology(button.dataset.filter);
  });
});

const traceRows = Object.entries(runtimeEvaluation.trace).filter(([key]) => key !== "trace_hash");
document.getElementById("traceSurface").innerHTML = traceRows
  .map(([key, values]) => `
    <article class="trace-item">
      <strong>${key.replaceAll("_", " ")}</strong>
      <p>${values.join("; ")}</p>
    </article>
  `)
  .join("");

document.getElementById("telemetryStream").innerHTML = runtimeEvaluation.telemetry
  .map(([time, event, detail]) => `
    <article class="telemetry-event">
      <strong>${event}</strong>
      <p>${detail}</p>
      <span>${time}</span>
    </article>
  `)
  .join("");

document.getElementById("authorityRef").textContent = runtimeEvaluation.result.enforcement_outcome.authority_ref;
document.getElementById("requestRef").textContent = runtimeEvaluation.request.request_id;
document.getElementById("targetRef").textContent = `${runtimeEvaluation.request.action} -> ${runtimeEvaluation.request.target}`;
document.getElementById("latencyRef").textContent = `${runtimeEvaluation.evidence.execution_context.latency_ms} ms`;
document.getElementById("decisionState").textContent = runtimeEvaluation.result.status.toUpperCase();
document.getElementById("decisionRationale").textContent = runtimeEvaluation.result.rationale;
document.getElementById("decisionConsequence").textContent = runtimeEvaluation.result.consequence;
document.getElementById("decisionNext").textContent = runtimeEvaluation.result.next;
document.querySelector(".gate-question strong").textContent = runtimeEvaluation.result.answer;
document.getElementById("traceHash").textContent = runtimeEvaluation.trace.trace_hash;

renderChronology();
