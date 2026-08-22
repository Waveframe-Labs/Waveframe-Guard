# Waveframe Guard v0.15.0 Release Notes

## Deterministic Target Enforcement

Guard v0.15.0 enforces deterministic target requirements from a compiled
authority at the execution boundary. Exact and prefix rules match literal,
case-sensitive targets; deny rules take precedence. Malformed scope and missing
or invalid scoped targets fail closed, while legacy target-free authorities
retain their existing decisions and evidence.

The commercial demo path is now explicit: the same actor and published
authority can allow a `README.md` mutation exactly once while blocking
`deployment/production.example.yml` before its callback runs.

## Preservation Timeout

`preservation_timeout_seconds` defaults to 10.0 seconds and applies only to
Cloud `POST /v1/preserve`. A timeout is treated as ambiguous because Cloud may
already have committed immutable evidence; Guard performs no blind automatic
retry. Local decisions and callback boundaries remain authoritative and
unchanged.

## Compatibility

CRI-CORE Contract Compiler v0.4.0 defines deterministic target requirements.
Guard v0.15.0 consumes the compiled authority artifacts and enforces them; it
does not become a policy compiler or add a compiler runtime dependency.
Waveframe Cloud v0.5.5 remains compatible and unchanged. The authoritative
matrix is in [`docs/getting-started/README.md`](docs/getting-started/README.md#release-compatibility-matrix).

## References

Closes #12 and #14 through PRs #13 and #15. References
Waveframe-Labs/Waveframe-Cloud#109.

This is release preparation only. No merge, tag, GitHub release, PyPI upload,
Cloud modification, or hosted acceptance is part of this change.
