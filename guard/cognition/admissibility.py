from __future__ import annotations

from typing import Any


def assess_admissibility(
    *,
    compiled_authority: dict[str, Any],
    execution_request: dict[str, Any],
    actor_identity: dict[str, Any],
    continuity_state: dict[str, Any] | None = None,
    replay_posture: dict[str, Any] | None = None,
    evidence_posture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    continuity_state = continuity_state or {}
    replay_posture = replay_posture or {}
    evidence_posture = evidence_posture or {}
    continuation_status = evidence_posture.get("continuation_status") or {}

    violated_constraints = []
    required_evidence = []
    continuity_requirements = []
    replay_obligations = []

    violated_constraints.extend(_role_constraints(compiled_authority, actor_identity))
    required_evidence.extend(
        _approval_evidence_requirements(
            compiled_authority=compiled_authority,
            execution_request=execution_request,
            evidence_posture=evidence_posture,
        )
    )
    violated_constraints.extend(
        _separation_of_duties_constraints(
            compiled_authority=compiled_authority,
            actor_identity=actor_identity,
            evidence_posture=evidence_posture,
        )
    )
    continuity_requirements.extend(_continuity_requirements(continuity_state))
    replay_obligations.extend(_replay_obligations(replay_posture))
    violated_constraints.extend(_continuation_constraints(continuation_status))
    if not continuity_requirements:
        continuity_requirements.extend(_continuation_requirements(continuation_status))
    if not replay_obligations:
        replay_obligations.extend(_continuation_replay_obligations(continuation_status))

    if violated_constraints or required_evidence:
        status = "blocked"
        rationale = _blocked_rationale(violated_constraints, required_evidence)
    elif continuity_requirements or replay_obligations:
        status = "escalated"
        rationale = "runtime posture requires revalidation or replay before execution"
    else:
        status = "admissible"
        rationale = "execution is admissible against compiled authority"

    enforcement_consequences = _enforcement_consequences(
        status=status,
        violated_constraints=violated_constraints,
        required_evidence=required_evidence,
        continuity_requirements=continuity_requirements,
        replay_obligations=replay_obligations,
    )

    return {
        "status": status,
        "rationale": rationale,
        "violated_constraints": violated_constraints,
        "required_evidence": required_evidence,
        "replay_obligations": replay_obligations,
        "continuity_requirements": continuity_requirements,
        "enforcement_consequences": enforcement_consequences,
        "continuation_status": continuation_status,
    }


def _role_constraints(authority: dict[str, Any], actor: dict[str, Any]) -> list[dict[str, Any]]:
    required_roles = authority.get("authority_requirements", {}).get("required_roles") or []
    if not required_roles:
        return []
    if actor.get("role") in required_roles:
        return []
    return [
        {
            "constraint": "required_role",
            "required_roles": list(required_roles),
            "observed_role": actor.get("role"),
            "rationale": "actor role is not authorized by compiled authority",
        }
    ]


def _approval_evidence_requirements(
    *,
    compiled_authority: dict[str, Any],
    execution_request: dict[str, Any],
    evidence_posture: dict[str, Any],
) -> list[dict[str, Any]]:
    requirements = compiled_authority.get("approval_requirements", {}).get("required") or []
    approvals = evidence_posture.get("approvals") or []
    missing = []
    amount = _execution_amount(execution_request)
    for requirement in requirements:
        if not _condition_applies(requirement.get("condition"), amount):
            continue
        role = requirement.get("role")
        if not _approval_for_role(approvals, role):
            missing.append(
                {
                    "evidence": "approval",
                    "role": role,
                    "condition": requirement.get("condition"),
                    "rationale": "required approval evidence is missing",
                }
            )
    return missing


def _separation_of_duties_constraints(
    *,
    compiled_authority: dict[str, Any],
    actor_identity: dict[str, Any],
    evidence_posture: dict[str, Any],
) -> list[dict[str, Any]]:
    if compiled_authority.get("invariants", {}).get("separation_of_duties") is not True:
        return []
    actor_id = actor_identity.get("id")
    approvals = evidence_posture.get("approvals") or []
    for approval in approvals:
        if approval.get("approved_by") == actor_id:
            return [
                {
                    "constraint": "separation_of_duties",
                    "actor_id": actor_id,
                    "approval_role": approval.get("role"),
                    "rationale": "actor cannot approve their own execution request",
                }
            ]
    return []


def _continuity_requirements(continuity_state: dict[str, Any]) -> list[dict[str, Any]]:
    requirements = list(continuity_state.get("requirements", []))
    if continuity_state.get("requires_revalidation") is True:
        requirements.append(
            {
                "requirement": "revalidation",
                "signals": list(continuity_state.get("signals", [])),
                "rationale": "continuity state requires runtime revalidation",
            }
        )
    return requirements


def _replay_obligations(replay_posture: dict[str, Any]) -> list[dict[str, Any]]:
    obligations = list(replay_posture.get("obligations", []))
    if replay_posture.get("required") is True and not obligations:
        obligations.append(
            {
                "obligation": "replay",
                "rationale": "execution must be linked to replay before enforcement",
            }
        )
    return obligations


def _continuation_constraints(continuation_status: dict[str, Any]) -> list[dict[str, Any]]:
    status = continuation_status.get("status")
    if status not in {"invalidated", "expired"}:
        return []
    return [
        {
            "constraint": "continuation_validity",
            "continuation_status": status,
            "dependency_failures": continuation_status.get("dependency_failures", []),
            "rationale": "continuation invalidated by runtime dependency state"
            if status == "invalidated"
            else "continuation expired before execution",
        }
    ]


def _continuation_requirements(continuation_status: dict[str, Any]) -> list[dict[str, Any]]:
    if continuation_status.get("status") != "revalidation_required":
        return []
    return [
        {
            "requirement": "continuation_revalidation",
            "rationale": "continuation requires runtime revalidation before execution",
        }
    ]


def _continuation_replay_obligations(continuation_status: dict[str, Any]) -> list[dict[str, Any]]:
    if continuation_status.get("status") != "escalation_required":
        return []
    return [
        {
            "obligation": "continuation_escalation",
            "rationale": "continuation requires escalation before execution",
        }
    ]


def _enforcement_consequences(
    *,
    status: str,
    violated_constraints: list[dict[str, Any]],
    required_evidence: list[dict[str, Any]],
    continuity_requirements: list[dict[str, Any]],
    replay_obligations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if status == "admissible":
        return [{"consequence": "allow_execution"}]
    if status == "blocked":
        return [
            {
                "consequence": "block_execution",
                "violated_constraints": violated_constraints,
                "required_evidence": required_evidence,
            }
        ]
    return [
        {
            "consequence": "escalate_execution",
            "continuity_requirements": continuity_requirements,
            "replay_obligations": replay_obligations,
        }
    ]


def _blocked_rationale(
    violated_constraints: list[dict[str, Any]],
    required_evidence: list[dict[str, Any]],
) -> str:
    if violated_constraints:
        return violated_constraints[0]["rationale"]
    if required_evidence:
        return required_evidence[0]["rationale"]
    return "execution is blocked"


def _approval_for_role(approvals: list[dict[str, Any]], role: str | None) -> dict[str, Any] | None:
    for approval in approvals:
        if approval.get("role") == role and approval.get("approved_by"):
            return approval
    return None


def _execution_amount(execution_request: dict[str, Any]) -> Any:
    arguments = execution_request.get("arguments")
    if isinstance(arguments, dict):
        return arguments.get("amount")
    return execution_request.get("amount")


def _condition_applies(condition: dict[str, Any] | None, amount: Any) -> bool:
    if not condition:
        return True
    if condition.get("field") != "amount":
        return False
    if amount is None:
        return True
    operator = condition.get("operator")
    value = condition.get("value")
    if operator == ">":
        return amount > value
    if operator == ">=":
        return amount >= value
    if operator == "<":
        return amount < value
    if operator == "<=":
        return amount <= value
    if operator == "==":
        return amount == value
    return False
