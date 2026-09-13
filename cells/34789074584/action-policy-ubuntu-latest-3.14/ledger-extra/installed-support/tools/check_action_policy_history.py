"""Canonical historical artifacts, executable with published Ledger 0.8 or source.

Use python -I for published-package measurement, python for the source measurement.
Test helpers supply identical historical authoring inputs; all Ledger functions are
resolved from the selected environment. No golden artifacts are rewritten.
"""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "tests"))
from test_policy_translation import _proposal, _confirmed, _approved
from governance_ledger.policy_translation_publication import finalize_policy_translation_authority_v3
from governance_ledger.policy_translation import render_policy_translation_review, get_policy_translation_capability_catalog, finalize_policy_translation_authority
from governance_ledger.domain_packs import get_builtin_domain_pack
from governance_ledger.publication_provenance import canonical_sha256

proposal = _proposal()
confirmation = _confirmed(proposal)
approval = _approved(proposal, confirmation)
v2 = finalize_policy_translation_authority(proposal, confirmation, approval,
    committed_by="ledger-committer", committed_at="2026-09-03T12:04:00Z",
    publication_id="publication-1", published_by="ledger-publisher", published_at="2026-09-03T12:05:00Z")
v3 = finalize_policy_translation_authority_v3(proposal, confirmation, approval,
    committed_by="ledger-committer", committed_at="2026-09-03T12:04:00Z",
    publication_id="publication-1", published_by="ledger-publisher", published_at="2026-09-03T12:05:00Z")
artifacts = {"catalog-1": get_policy_translation_capability_catalog(),
             "pack-1": get_builtin_domain_pack("repository-changes", "1.0.0"),
             "proposal": proposal, "confirmation": confirmation, "approval": approval,
             "review-wording": render_policy_translation_review(proposal, confirmation),
             "v2-publication": v2, "v3-publication": v3}
report = {"artifact_hashes": {name: canonical_sha256(value) for name, value in artifacts.items()},
          "golden_file_sha256": {str(path.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in sorted((ROOT / "tests/fixtures/golden_path").rglob("*.json"))}}
print(json.dumps(report, indent=2))
