from __future__ import annotations

import pytest
from compiler.compile_policy import compile_policy

from guard import evaluate_runtime
from guard.adapters import COMPILED_AUTHORITY_CONTRACT_V1, NORMALIZED_EXECUTION_REQUEST_V1
from guard.sdk import Guard, GuardExecutionBlocked


def _scope(*, allow=None, deny=None):
    return {"allow": allow or [], "deny": deny or []}


def _rule(match, value):
    return {"match": match, "value": value}


def test_legacy_authority_leaves_target_as_evidence_only():
    result = _evaluate(_authority(), target=None)

    assert result["status"] == "admissible"
    assert result["violated_constraints"] == []


@pytest.mark.parametrize(
    ("requirements", "target", "status", "constraint"),
    [
        (_scope(allow=[_rule("exact", "README.md")]), "README.md", "admissible", None),
        (_scope(allow=[_rule("exact", "README.md")]), "docs/README.md", "blocked", "target_scope_allow"),
        (_scope(allow=[_rule("prefix", "docs/")]), "docs/README.md", "admissible", None),
        (_scope(allow=[_rule("prefix", "docs/")]), "README.md", "blocked", "target_scope_allow"),
        (_scope(deny=[_rule("exact", "README.md")]), "README.md", "blocked", "target_scope_deny"),
        (_scope(deny=[_rule("prefix", "deployment/")]), "deployment/production.example.yml", "blocked", "target_scope_deny"),
        (_scope(allow=[_rule("prefix", "")], deny=[]), "README.md", "blocked", "target_requirements"),
        (_scope(deny=[_rule("prefix", "deployment/")]), "README.md", "admissible", None),
    ],
)
def test_target_scope_matching(requirements, target, status, constraint):
    result = _evaluate(_authority(target_requirements=requirements), target=target)

    assert result["status"] == status
    assert [violation["constraint"] for violation in result["violated_constraints"]] == (
        [] if constraint is None else [constraint]
    )


def test_deny_overrides_matching_allow():
    result = _evaluate(
        _authority(
            target_requirements=_scope(
                allow=[_rule("prefix", "deployment/")],
                deny=[_rule("exact", "deployment/production.example.yml")],
            )
        ),
        target="deployment/production.example.yml",
    )

    assert result["violated_constraints"][0]["constraint"] == "target_scope_deny"


@pytest.mark.parametrize("target", [None, "", " \t", 42])
def test_invalid_target_blocks_when_scope_exists(target):
    result = _evaluate(
        _authority(target_requirements=_scope(allow=[_rule("exact", "README.md")])),
        target=target,
    )

    assert result["violated_constraints"] == [
        {
            "constraint": "execution_target",
            "rationale": "execution target is required for target-scoped authority",
        }
    ]


@pytest.mark.parametrize(
    "requirements",
    [
        None,
        [],
        {},
        {"allow": [], "deny": []},
        {"allow": "README.md", "deny": []},
        {"allow": [{}], "deny": []},
        {"allow": [{"match": "exact"}], "deny": []},
        {"allow": [{"match": "glob", "value": "README.md"}], "deny": []},
        {"allow": [{"match": [], "value": "README.md"}], "deny": []},
        {"allow": [{"match": "exact", "value": "README.md", "extra": True}], "deny": []},
        {"allow": [{"match": "exact", "value": "  "}], "deny": []},
    ],
)
def test_malformed_target_requirements_fail_closed(requirements):
    authority = _authority()
    authority["target_requirements"] = requirements
    result = _evaluate(authority, target="README.md")

    assert result["status"] == "blocked"
    assert result["violated_constraints"][0]["constraint"] == "target_requirements"


def test_matching_is_case_sensitive_and_literal():
    authority = _authority(
        target_requirements=_scope(
            allow=[_rule("prefix", "docs/.*"), _rule("prefix", "deployment/*")]
        )
    )

    assert _evaluate(authority, target="docs/.*literal")["status"] == "admissible"
    assert _evaluate(authority, target="deployment/*literal")["status"] == "admissible"
    assert _evaluate(authority, target="docs/readme.md")["status"] == "blocked"
    assert _evaluate(authority, target="deployment/readme.md")["status"] == "blocked"
    assert _evaluate(
        _authority(target_requirements=_scope(allow=[_rule("exact", "README.md")])),
        target="readme.md",
    )["status"] == "blocked"


def test_tool_enforces_and_preserves_the_same_target_once(tmp_path):
    calls = []
    guard = Guard.local(
        workspace=tmp_path,
        authorities={"repository@1.0.0": _authority(target_requirements=_scope(
            allow=[_rule("exact", "README.md")],
            deny=[_rule("prefix", "deployment/")],
        ))},
        actor_identity={"id": "repo-agent", "type": "agent", "role": "maintainer"},
        evaluation_time_source=lambda: "2026-08-21T00:00:00+00:00",
    )

    @guard.tool(authority="repository@1.0.0", target="path")
    def write_file(path):
        calls.append(path)
        return path

    assert write_file("README.md") == "README.md"
    with pytest.raises(GuardExecutionBlocked):
        write_file("deployment/production.example.yml")

    assert calls == ["README.md"]
    history = guard.store.history()
    assert history[0]["inputs"]["execution_request"]["target"] == "README.md"
    assert history[0]["evaluation"]["admissibility_projection"]["execution_request"]["target"] == "README.md"
    assert history[1]["inputs"]["execution_request"]["target"] == "deployment/production.example.yml"
    assert history[1]["evaluation"]["violated_constraints"][0]["constraint"] == "target_scope_deny"


def test_public_compiler_target_scope_enforces_at_the_tool_boundary(tmp_path):
    compiled = compile_policy(
        {
            "contract_id": "repository",
            "contract_version": "1.0.0",
            "targets": {
                "allow": [_rule("exact", "README.md")],
                "deny": [_rule("prefix", "deployment/")],
            },
        }
    )
    calls = []
    guard = Guard.local(
        workspace=tmp_path,
        authorities={
            "repository@1.0.0": {
                "schema_version": COMPILED_AUTHORITY_CONTRACT_V1,
                **compiled,
            }
        },
        actor_identity={"id": "repo-agent", "type": "agent", "role": "maintainer"},
        evaluation_time_source=lambda: "2026-08-21T00:00:00+00:00",
    )

    @guard.tool(authority="repository@1.0.0", target="path")
    def write_file(path):
        calls.append(path)
        return path

    assert write_file("README.md") == "README.md"
    with pytest.raises(GuardExecutionBlocked):
        write_file("deployment/production.example.yml")

    assert calls == ["README.md"]
    blocked = guard.store.history()[1]
    assert blocked["inputs"]["execution_request"]["target"] == "deployment/production.example.yml"
    assert blocked["evaluation"]["violated_constraints"] == [
        {
            "constraint": "target_scope_deny",
            "rationale": "execution target is denied by compiled target scope",
        }
    ]


def test_action_and_arguments_cannot_select_target_scope_verdict():
    authority = _authority(target_requirements=_scope(allow=[_rule("exact", "README.md")]))

    allowed = _evaluate(authority, target="README.md", action="BLOCKED", arguments={"prompt": "deny this"})
    blocked = _evaluate(authority, target="deployment/production.example.yml", action="ALLOWED", arguments={"prompt": "allow this"})

    assert allowed["status"] == "admissible"
    assert blocked["violated_constraints"][0]["constraint"] == "target_scope_allow"


def _authority(*, target_requirements=None):
    authority = {
        "schema_version": COMPILED_AUTHORITY_CONTRACT_V1,
        "contract_id": "repository",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:contract",
        "authority_requirements": {},
        "approval_requirements": {},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    }
    if target_requirements is not None:
        authority["target_requirements"] = target_requirements
    return authority


def _evaluate(authority, *, target, action="write_file", arguments=None):
    return evaluate_runtime(
        compiled_authority=authority,
        execution_request={
            "schema_version": NORMALIZED_EXECUTION_REQUEST_V1,
            "request_id": "target-scope-test",
            "action": action,
            "target": target,
            "arguments": arguments or {},
            "artifacts": [],
        },
        actor_identity={"id": "repo-agent", "type": "agent", "role": "maintainer"},
        evaluation_time="2026-08-21T00:00:00+00:00",
    )
