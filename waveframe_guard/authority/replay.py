"""Revalidate retained native publications for logical local replay only."""

from pathlib import Path

from .exceptions import AuthorityVerificationError
from .types import Bundle, RegistryEntry
from .verifier import AuthorityVerifier
from .runtime_facts import VerifiedRuntimeAuthority


def verify_recorded_publication(publication, evidence):
    if not isinstance(publication, dict) or set(publication) != {"bundle", "receipt"}:
        raise AuthorityVerificationError("action replay requires the retained native publication pair")
    contract = evidence["compiled_contract"]
    bundle = evidence["authority_bundle"]
    receipt = evidence["publication_receipt"]
    # Paths are placeholders: Ledger verifies the retained artifacts, with the
    # recorded registry identity and hashes. Replay does not refresh lifecycle.
    entry = RegistryEntry(
        authority_ref=evidence["authority"]["authority_ref"],
        contract_id=contract["contract_id"], contract_version=contract["contract_version"],
        contract_hash=contract["contract_hash"], bundle_hash=bundle["bundle_hash"],
        receipt_hash=receipt["receipt_hash"], publication_id=bundle["publication_id"],
        bundle_ref=bundle["logical_ref"], receipt_ref=receipt["logical_ref"],
        bundle_path=Path("recorded-bundle"), receipt_path=Path("recorded-receipt"),
    )
    loaded = AuthorityVerifier().verify(Bundle(
        registry_entry=entry, payload=publication["bundle"], receipt_payload=publication["receipt"],
        bundle_hash=entry.bundle_hash, receipt_hash=entry.receipt_hash,
        bundle_path=entry.bundle_path, receipt_path=entry.receipt_path,
        bundle_ref=entry.bundle_ref, receipt_ref=entry.receipt_ref,
    ))
    verified = VerifiedRuntimeAuthority.from_loaded(loaded)
    if verified.evidence() != {key: value for key, value in evidence.items() if key != "runtime_facts"}:
        raise AuthorityVerificationError("recorded publication evidence changed")
    return verified
