# Security Policy

## Overview

Waveframe Guard enforces deterministic execution control for AI-initiated actions before they reach downstream systems.

Because it sits at the execution boundary for sensitive operations such as writes, deletes, deployments, transfers, and other state-changing actions, security is a core concern.

---

## Supported Versions

Security updates are applied to the latest release line only.

Current supported release line:

- `0.2.x`

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

- executing downstream actions
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

Ensure that:

- all state-changing actions pass through Guard
- no alternative execution paths exist
- no fallback logic bypasses policy enforcement

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

- all blocked actions
- all pending actions awaiting authorization
- all allowed actions affecting sensitive systems or data
- actor, role-resolution, and policy-version context

This supports auditability, incident response, and change review.

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
