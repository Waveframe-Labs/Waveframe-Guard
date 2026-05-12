from pathlib import Path
import json

from .context import install_guard
from .contracts import load_contract
from .execute import GovernanceError, execute as execute_guarded
from .result import GovernedExecutionResult


class GovernedRuntime:
    def __init__(self, *, registry_path):
        self.registry_path = Path(registry_path)
        self.registry = self._load_registry()

    def execute(
        self,
        *,
        actor,
        contract_id,
        fn,
        args=None,
        kwargs=None,
        raise_on_block=True,
    ):
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

    def _load_registry(self):
        with self.registry_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _load_contract(self, contract_id):
        entry = self._lookup_contract(contract_id)
        contract_path = self._contract_path(entry)
        return load_contract(contract_path)

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
