# Waveframe Guard v0.14.0 Release Notes

## External Agent Integration

Waveframe Guard v0.14.0 stabilizes the public, provider-neutral enforcement path for existing Python agent tools. Customers install the package, create `Guard.cloud(...)` with explicit runtime and actor identity plus a versioned authority reference, and wrap the function that can mutate real state with `Guard.tool(...)`.

The integration does not require Ollama, a particular agent framework, or a Waveframe repository checkout. The customer's model and orchestration layer remain unchanged; Guard owns only the enforcement boundary immediately before execution.

## Highlights

- Added the packaged external-agent quickstart and console entry point.
- Added provider-neutral `Guard.tool(...)` wrappers for ordinary Python callables.
- Added hosted authority resolution through `Guard.cloud(authority="name@x.y.z")`.
- Added explicit Cloud URL, runtime credential, organization, runtime identity, environment, actor identity, and authority configuration.
- Added runtime registration, heartbeat, and post-execution attestation.
- Added preservation package, receipt, and proof identifiers to successful quickstart output.
- Demonstrated one allowed action, one blocked action, and exactly one underlying mutation.

## Acceptance Hardening

The external-agent quickstart now treats Cloud integration as an acceptance contract. It succeeds only when runtime registration and heartbeat succeed, the allowed callback executes, the blocked callback does not execute, exactly one mutation occurs, both decisions are preserved with their required identifiers, and both execution attestations succeed.

Failures report the affected action, sanitized HTTP status, error type, and Cloud error without exposing credentials. Guard's general Cloud behavior remains best effort; this strict contract applies only to the acceptance quickstart.

Saved evaluations are detached from live result objects before hashing. This prevents later `run_id` decoration from mutating the preservation payload after its `record_hash` has been calculated.

## Compatibility

The authoritative release compatibility matrix is maintained in [`docs/getting-started/README.md`](docs/getting-started/README.md#release-compatibility-matrix). Waveframe Cloud 0.5.0 is the coordinated recommended release and remains marked as not yet published during this release-preparation phase.

## Verification

- Focused external-agent and Cloud-client tests: `41 passed`.
- Complete Guard suite: `226 passed`.
- `python -m build`: built `waveframe_guard-0.14.0.tar.gz` and `waveframe_guard-0.14.0-py3-none-any.whl`.
- `python -m twine check dist/*`: passed for both distributions.
- Fresh wheel-only virtual environment outside the checkout: public and metadata versions `0.14.0`, imports resolved from the virtual environment, and no source-tree shadowing.
- Clean-machine external-agent acceptance: all expected markers, two preservation requests, and two attestation requests.

This is release preparation only. No tag, GitHub release, or PyPI publication is part of this change.
