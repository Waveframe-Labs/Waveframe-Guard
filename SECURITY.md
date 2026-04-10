# Security Policy

## Overview

Waveframe Guard enforces execution control over AI-generated actions, particularly in financial systems.

Because this library operates at the decision boundary for potentially sensitive operations (e.g., fund transfers), security is a core concern.

---

## Supported Versions

This project is under active development.

Security updates will be applied to the latest version only.

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

- evaluating whether an action is allowed or blocked
- enforcing deterministic decision logic at execution boundaries

Waveframe Guard is **not responsible for**:

- executing actions
- managing authentication or identity systems
- storing sensitive financial data
- handling secrets or credentials

These responsibilities remain with the integrating system.

---

## Security Considerations

When using Waveframe Guard in production:

### 1. Treat decisions as authoritative

If an action is marked as:
```python
{"allowed": False}
````

It must not be executed.

Bypassing this check defeats the purpose of enforcement.

---

### 2. Protect the execution path

Ensure that:

* all state-changing actions pass through the guard
* no alternative execution paths exist
* no "fallback" execution logic bypasses enforcement

---

### 3. Validate inputs upstream

Waveframe Guard assumes:

* actions are well-formed
* actor identities are meaningful

Input validation and identity verification should be handled before calling the SDK.

---

### 4. Policy integrity

Policies define governance rules.

Ensure:

* policies are loaded from trusted sources
* policy files are not tampered with
* versioning is controlled

---

### 5. Logging and monitoring

For production systems, it is recommended to log:

* all blocked actions
* all allowed actions involving financial changes
* actor and approval context

This enables auditability and incident response.

---

## Future Enhancements

Planned improvements include:

* signed policy verification
* stronger contract integrity guarantees
* optional audit logging integrations

---

## Disclaimer

Waveframe Guard provides enforcement logic but does not replace a complete security architecture.

It should be used as part of a broader system that includes:

* authentication
* authorization
* monitoring
* audit controls

---

<div align="center">
  <sub>© 2026 Waveframe Labs — Independent Open-Science Research Entity</sub>
</div>