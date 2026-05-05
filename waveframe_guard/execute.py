from proposal_normalizer.build_proposal import build_proposal
from cricore.api import evaluate_structured

from .context import get_context


def execute(fn, *, args=None, kwargs=None, actor=None, contract=None):
    ctx = get_context()

    actor = actor or ctx.get("actor")
    contract = contract or ctx.get("contract")
    mode = ctx.get("mode", "local")

    if actor is None or contract is None:
        raise ValueError("Missing actor or contract")

    proposal = build_proposal(
        proposal_id="auto",
        actor=actor,
        mutation=_infer_mutation(fn, args, kwargs),
        contract={
            "id": contract["contract_id"],
            "version": contract["contract_version"],
            "hash": contract["contract_hash"],
        },
        artifact_paths=[],
    )

    result = evaluate_structured(
        proposal=proposal,
        compiled_contract=contract,
        run_context=_build_run_context(actor, contract, mode),
    )

    if not result.commit_allowed:
        raise PermissionError("Execution blocked")

    return fn(*(args or []), **(kwargs or {}))


def _infer_mutation(fn, args, kwargs):
    return {
        "domain": "python",
        "resource": fn.__name__,
        "action": "call",
    }


def _build_run_context(actor, contract, mode):
    required_roles = (
        contract.get("authority_requirements", {}).get("required_roles")
        or [actor.get("role")]
    )

    return {
        "mode": mode,
        "identities": {
            "actors": [actor],
            "required_roles": required_roles,
            "conflict_flags": {},
        },
    }
