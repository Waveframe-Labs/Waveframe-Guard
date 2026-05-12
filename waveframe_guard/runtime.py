from pathlib import Path
from datetime import datetime, timezone
import json

from cricore.api import evaluate_structured

from .context import install_guard
from .contracts import load_contract
from .execute import (
    GovernanceError,
    _blocked_reason as decision_blocked_reason,
    _build_run_context,
    execute as execute_guarded,
)
from .result import GovernedExecutionResult


class GovernedRuntime:
    def __init__(self, *, registry_path, audit_path=None):
        self.registry_path = Path(registry_path)
        self.registry = self._load_registry()
        self.audit_path = Path(audit_path) if audit_path is not None else None
        self.audit_events = []
        self.last_event = None
        self.actor = None
        self.contract_id = None

    def install_actor(self, actor):
        self.actor = actor
        return self

    def bind_contract(self, contract_id):
        self.contract_id = contract_id
        return self

    def execute(
        self,
        *,
        actor=None,
        contract_id=None,
        fn,
        args=None,
        kwargs=None,
        raise_on_block=True,
    ):
        actor = self._resolve_actor(actor)
        contract_id = self._resolve_contract_id(contract_id)
        contract = self._load_contract(contract_id)

        install_guard(
            actor=actor,
            contract=contract,
            mode="local",
        )

        try:
            value = execute_guarded(
                fn,
                args=args or (),
                kwargs=kwargs or {},
                actor=actor,
                contract=contract,
            )
        except GovernanceError as exc:
            error = str(exc)
            event = self._build_event(
                actor=actor,
                contract=contract,
                execution_type="function",
                allowed=False,
                reason=self._blocked_reason(error),
                error=error,
                target=getattr(fn, "__name__", None),
            )
            self._emit_event(event)
            if raise_on_block:
                raise

            return GovernedExecutionResult(
                allowed=False,
                reason=self._blocked_reason(error),
                error=error,
                event=event,
                **self._contract_metadata(contract),
            )

        event = self._build_event(
            actor=actor,
            contract=contract,
            execution_type="function",
            allowed=True,
            reason="execution allowed",
            target=getattr(fn, "__name__", None),
        )
        self._emit_event(event)

        if raise_on_block:
            return value

        return GovernedExecutionResult(
            allowed=True,
            reason="execution allowed",
            value=value,
            event=event,
            **self._contract_metadata(contract),
        )

    def execute_proposal(
        self,
        proposal,
        *,
        actor=None,
        contract_id=None,
        raise_on_block=True,
    ):
        actor = self._resolve_actor(actor)
        contract_id = self._resolve_contract_id(contract_id)
        contract = self._load_contract(contract_id)

        install_guard(
            actor=actor,
            contract=contract,
            mode="local",
        )

        decision = evaluate_structured(
            proposal=proposal,
            compiled_contract=contract,
            run_context=_build_run_context(actor, contract, "local"),
        )

        if decision.commit_allowed:
            event = self._build_event(
                actor=actor,
                contract=contract,
                execution_type="proposal",
                allowed=True,
                reason="execution allowed",
                target=proposal.get("proposal_id") if isinstance(proposal, dict) else None,
            )
            self._emit_event(event)
            return GovernedExecutionResult(
                allowed=True,
                reason="execution allowed",
                value=proposal,
                event=event,
                **self._contract_metadata(contract),
            )

        reason = decision_blocked_reason(decision)
        error = f"Execution blocked: {reason}"
        event = self._build_event(
            actor=actor,
            contract=contract,
            execution_type="proposal",
            allowed=False,
            reason=reason,
            error=error,
            target=proposal.get("proposal_id") if isinstance(proposal, dict) else None,
        )
        self._emit_event(event)
        if raise_on_block:
            raise GovernanceError(error)

        return GovernedExecutionResult(
            allowed=False,
            reason=reason,
            error=error,
            event=event,
            **self._contract_metadata(contract),
        )

    def _load_registry(self):
        with self.registry_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _load_contract(self, contract_id):
        entry = self._lookup_contract(contract_id)
        contract_path = self._contract_path(entry)
        return load_contract(contract_path)

    def _resolve_actor(self, actor):
        resolved = actor or self.actor
        if resolved is None:
            raise ValueError("Missing actor")
        return resolved

    def _resolve_contract_id(self, contract_id):
        resolved = contract_id or self.contract_id
        if resolved is None:
            raise ValueError("Missing contract_id")
        return resolved

    def _lookup_contract(self, contract_id):
        contracts = self.registry.get("contracts", self.registry)

        if isinstance(contracts, dict):
            if contract_id not in contracts:
                raise KeyError(f"Unknown contract_id: {contract_id}")
            return contracts[contract_id]

        if isinstance(contracts, list):
            for entry in contracts:
                if entry.get("contract_id") == contract_id or entry.get("id") == contract_id:
                    return entry

        raise KeyError(f"Unknown contract_id: {contract_id}")

    def _contract_path(self, entry):
        if isinstance(entry, str):
            path = Path(entry)
        elif isinstance(entry, dict):
            path_value = (
                entry.get("path")
                or entry.get("contract_path")
                or entry.get("artifact")
            )
            if path_value is None:
                raise ValueError("Registry entry is missing a contract path")
            path = Path(path_value)
        else:
            raise ValueError("Registry entry must be a path string or object")

        if path.is_absolute():
            return path

        return self.registry_path.parent / path

    def _contract_metadata(self, contract):
        return {
            "contract_id": contract.get("contract_id"),
            "contract_version": contract.get("contract_version"),
            "contract_hash": contract.get("contract_hash"),
        }

    def _build_event(
        self,
        *,
        actor,
        contract,
        execution_type,
        allowed,
        reason,
        error=None,
        target=None,
    ):
        event = {
            "event_type": "governed_execution",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_type": execution_type,
            "allowed": allowed,
            "reason": reason,
            "actor": actor,
            **self._contract_metadata(contract),
        }

        if error is not None:
            event["error"] = error

        if target is not None:
            event["target"] = target

        return event

    def _emit_event(self, event):
        self.last_event = event
        self.audit_events.append(event)

        if self.audit_path is None:
            return

        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")

    def _blocked_reason(self, error):
        prefix = "Execution blocked: "
        if error.startswith(prefix):
            return error[len(prefix):]

        return error
