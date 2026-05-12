from pathlib import Path
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
    def __init__(self, *, registry_path):
        self.registry_path = Path(registry_path)
        self.registry = self._load_registry()
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
            if raise_on_block:
                raise

            error = str(exc)
            return GovernedExecutionResult(
                allowed=False,
                reason=self._blocked_reason(error),
                error=error,
                **self._contract_metadata(contract),
            )

        if raise_on_block:
            return value

        return GovernedExecutionResult(
            allowed=True,
            reason="execution allowed",
            value=value,
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
            return GovernedExecutionResult(
                allowed=True,
                reason="execution allowed",
                value=proposal,
                **self._contract_metadata(contract),
            )

        reason = decision_blocked_reason(decision)
        error = f"Execution blocked: {reason}"
        if raise_on_block:
            raise GovernanceError(error)

        return GovernedExecutionResult(
            allowed=False,
            reason=reason,
            error=error,
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

    def _blocked_reason(self, error):
        prefix = "Execution blocked: "
        if error.startswith(prefix):
            return error[len(prefix):]

        return error
