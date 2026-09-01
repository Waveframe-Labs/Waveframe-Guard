# System Boundaries

## Canonical invariant

Guard evaluates admissibility against compiled authority.
Guard never derives governance meaning from raw policy text.

This invariant is the primary system integrity rule. Guard may load, cache, verify,
project, and evaluate compiled authority. It must not interpret raw policy language,
extract governance semantics, or define the meaning of governance concepts.

## Guard owns

Guard owns runtime behavior at the execution edge:

- execution admissibility
- runtime evaluation
- runtime telemetry
- runtime chronology
- runtime enforcement cognition
- execution posture rendering
- local persistent runtime state for runs, leases, dependencies, and release
  validations

Guard answers one question:

> Is this execution admissible?

Guard does not answer:

> What does governance mean?

## Guard does not own

Guard must not own governance meaning. In particular, Guard must not contain:

- a semantic compiler folder
- a governance extraction folder
- duplicated governance authority schema definitions
- local compiled-authority contract classes
- local raw-policy compilation functions

Forbidden examples inside Guard:

```python
class CompiledAuthorityContract:
    ...
```

```python
def compile_policy(...):
    ...
```

Allowed examples are dependencies on external authority-producing systems:

```python
from governance_ledger.semantics.compiler import ...
from governance_ledger.semantics.execution_projection import ...
from cri_core import ...
```

Guard may consume those outputs. It may not recreate them.

## Proposed structural boundary

The intended Guard shape is:

```text
waveframe-guard/
    guard/
        enforcement/
        telemetry/
        runtime/
        cognition/
        sdk/
        adapters/
        projections/
    ui/
    server/
    tests/
    docs/
```

The absence of compiler and extraction folders is intentional:

```text
NO semantic compiler folder
NO governance extraction folder
NO schema duplication
```

## Dependency rule

Guard can depend on compiled authority and execution projection interfaces, but
the direction of meaning must stay one-way:

```text
Governance Ledger / semantic authority systems
        compile, define, and project governance meaning
        |
        v
Guard
        evaluates execution admissibility at runtime
```

If a change causes Guard to derive, infer, or redefine governance meaning, that
change crosses the system boundary and must be moved out of Guard.

## Intake rule

Guard accepts `compiled_authority_contract.v1` through the legacy compatibility
boundary. It accepts `compiled_authority_contract.v2` only after the complete
Ledger bundle and publication receipt have been verified; direct v2 contract
injection is rejected. Raw policy text and semantic extraction payloads remain
inadmissible.

Ledger defines domain vocabulary and the runtime fact schema. Guard owns the
trusted, deterministic binding from an intercepted proposal to those selected
facts. That binding may reject, type-check, and supply facts; it must not parse
policy prose, guess defaults, or create a global cross-domain lexicon.

Execution requests must also arrive through a normalization boundary. Guard may
call a Proposal Normalizer adapter when available, but Guard must not duplicate
proposal normalization rules locally.

## Persistent organizational runtime

Guard may persist local organizational runtime state in
`.guard-local/guard-runtime.sqlite3` so continuation governance can survive
process restarts. This transitional local layer may contain organization and
workspace context, actors, compiled authority references, runs, continuation
leases, release validations, runtime dependencies, and release queue rows.

This is not Cloud. It does not own managed tenancy, fleet-wide audit,
organization administration, policy publishing, semantic interpretation, or
centralized governance history.
