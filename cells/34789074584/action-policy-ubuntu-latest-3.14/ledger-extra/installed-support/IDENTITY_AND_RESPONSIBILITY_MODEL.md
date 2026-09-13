# Identity And Responsibility Model

Ledger models governance identity and responsibility as semantic authority meaning. It records who or what is expected to carry governance responsibility, how approval authority is bound, whether delegation is allowed, and which identity continuity expectations matter for replay and resumed workflows.

Ledger does not authenticate actors, grant permissions, enforce approvals, or verify runtime identity. Guard and Cloud own runtime admissibility, evidence verification, attestation, and identity checks.

## Core Primitives

- `governance_actor`: a human role, system role, team, agent, or external party that participates in governance responsibility.
- `authority_role`: a role that can approve, review, override, attest, or recommend governance action.
- `delegated_authority`: authority transferred or delegated from one actor or role to another.
- `approval_responsibility`: the operational responsibility carried by an approval role.
- `accountability_boundary`: the boundary where responsibility is assigned or handed off.
- `independence_constraint`: a separation-of-duties expectation such as no self-approval or dual control.
- `attestation_requirement`: a requirement that an operator, reviewer, or actor identity is attested.
- `identity_continuity`: the expectation that resumed or replayed governance remains bound to the same actor or role posture.
- `identity_revocation`: revocation of actor or role authority and its continuity effect.

## Canonical Artifacts

`governance_actor.v1` records the accountable actor or role:

```json
{
  "schema_version": "governance_actor.v1",
  "actor_id": "treasury-governance",
  "actor_type": "human_role",
  "authority_scope": ["transfer_approval"],
  "delegation_allowed": false,
  "attestation_required": true,
  "identity_continuity_required": true
}
```

`authority_role_binding.v1` binds a role to responsibility:

```json
{
  "schema_version": "authority_role_binding.v1",
  "role_id": "treasury-governance",
  "actor_ref": "treasury-governance",
  "responsibilities": ["approval_responsibility"],
  "accountability_boundary": "governance_approval",
  "delegation_posture": "not_allowed"
}
```

`approval_chain_semantics.v1` records approval chain structure:

```json
{
  "schema_version": "approval_chain_semantics.v1",
  "required_approval_count": 2,
  "required_roles": ["finance", "independent-reviewer"],
  "independence_required": true,
  "self_approval_prohibited": true,
  "delegation_posture": "not_allowed",
  "attestation_required": true
}
```

`identity_continuity_semantics.v1` records continuity expectations:

```json
{
  "schema_version": "identity_continuity_semantics.v1",
  "identity_continuity_required": true,
  "resume_identity_check": "actor_or_role_binding_must_remain_valid",
  "identity_revocation_effect": "revoked_identity_invalidates_resume",
  "runtime_enforced_by": "Guard/Cloud"
}
```

## Extraction Semantics

Ledger deterministically recognizes policy language such as:

- must be approved by finance
- requires independent reviewer
- cannot self-approve
- dual control
- delegated authority
- security team approval
- manager override
- break glass approval
- requires attested operator
- human-in-the-loop
- AI-generated recommendation

The extracted meaning remains candidate semantics until operator confirmation. Unresolved independence, delegation, or attestation ambiguity must stay explicit.

## Diagnostics

Identity diagnostics are advisory and non-blocking:

- `Approval Independence Ambiguity`: approval semantics imply separation-of-duties but independent actors are undefined.
- `Delegation Ambiguity`: delegated authority language exists without delegation boundaries.
- `Identity Continuity Gap`: resumable workflow semantics exist without identity continuity expectations.
- `Attestation Requirement Gap`: high-impact governance posture exists without actor attestation semantics.

## Boundary

Ledger owns semantic identity modeling and responsibility interpretation.

Guard and Cloud own:

- authenticating actors,
- enforcing approval decisions,
- verifying attested identity evidence,
- validating runtime identity continuity,
- deciding admissibility.
