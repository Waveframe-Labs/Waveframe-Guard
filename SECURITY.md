# Security Policy

## Overview

Waveframe Guard evaluates and enforces mediated actions before invoking their
wrapped callbacks. Actions reaching the same capability through alternate
functions, tools, processes, credentials or API paths are outside its guarantee.

The canonical [mediation and bypass threat model](docs/architecture/REPOSITORY_WORKSPACE.md#mediation-and-bypass-threat-model)
defines trusted components, deployment guidance and operator verification.
Repository mutation supports only the OS/filesystem and existing-file operations
listed there; generic callable examples do not establish filesystem semantics.

---

## Supported Versions

Security updates are applied to the latest release line only.

Current supported release line:

- `v0.16.x`

---

## Reporting a Vulnerability

If you discover a vulnerability, please report it privately.

**Contact:**
- Email: swright@waveframelabs.org

Please include:
- description of the issue
- steps to reproduce
- potential impact

We will acknowledge receipt within 48 hours and work toward a resolution.

---

## Scope of Responsibility

Waveframe Guard is responsible for:

- evaluating whether a proposed action is allowed, pending, or blocked
- enforcing deterministic decision logic at execution boundaries
- preserving policy-bound audit traces for governance review

Waveframe Guard is **not responsible for**:

- implementing the customer's downstream mutation logic (the SDK invokes the
  trusted callback when its mediated decision permits it)
- managing authentication or identity proofing systems
- storing customer system data beyond audit metadata
- handling secrets or credentials for integrating platforms

These responsibilities remain with the integrating system.

---

## Security Considerations

When using Waveframe Guard in production:

### 1. Treat decisions as authoritative

If an action is marked as:

```python
{"allowed": False}
```

It must not be executed.

Bypassing this check defeats the purpose of enforcement.

---

### 2. Protect the execution path

Identify the exact wrapped callable and verify one allowed and one blocked
mediated action, including zero callback invocations for the blocked action.
Separately verify the agent's tools, credentials and effective permissions do
not provide an alternate mutation path. A passing Guard test or connected runtime
does not establish this. Follow the [least-privilege deployment and operator
procedure](docs/architecture/REPOSITORY_WORKSPACE.md#operator-verification).

---

### 3. Validate inputs upstream

Waveframe Guard assumes:

- actions are structurally well-formed
- actor identities are meaningful to the integrating system

Input validation and identity verification should be handled before calling the SDK or API.

---

### 4. Protect policy integrity

Policies define governance rules and execution structure.

Ensure that:

- policies are loaded from trusted sources
- stored policy versions are not tampered with
- versioning and promotion are controlled

---

### 5. Monitor audit records

For production systems, it is recommended to log and review:

- observed blocked mediated actions
- observed pending mediated actions awaiting authorization
- observed allowed mediated actions affecting sensitive systems or data
- actor, role-resolution, and policy-version context

This supports auditability, incident response, and change review. Guard evidence
is not a complete inventory of unmediated actions; monitor alternate paths using
independent infrastructure records.

---

## Future Enhancements

Planned improvements include:

- signed policy verification
- stronger contract integrity guarantees
- additional audit export and evidence tooling

---

## Disclaimer

Waveframe Guard provides deterministic enforcement logic, but it does not replace a complete security architecture.

It should be used as part of a broader system that includes:

- authentication
- authorization
- monitoring
- audit controls
- infrastructure and application hardening

---

<div align="center">
  <sub>© 2026 Waveframe Labs</sub>
</div>
