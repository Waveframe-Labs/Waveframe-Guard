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
