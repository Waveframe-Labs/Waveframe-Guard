# ---------------------------
# SEED SCRIPT — WAVEFRAME GUARD
# ---------------------------

import secrets
import hashlib
from datetime import datetime

from db import (
    SessionLocal,
    init_db,
    hash_api_key,
    Organization,
    APIKey,
    Policy,
    PolicyVersion,
)


# ---------------------------
# CONFIG (EDIT THIS LATER)
# ---------------------------

ORG_NAME = "Acme Corp"
POLICY_NAME = "finance-core"


# ---------------------------
# SAMPLE POLICY (START SIMPLE)
# ---------------------------

SAMPLE_POLICY = {
    "required_roles": ["proposer", "accountable"],
    "rules": [
        {
            "type": "separation_of_duties",
            "description": "Proposer and accountable must be different"
        }
    ]
}


# ---------------------------
# MAIN
# ---------------------------

def run():
    print("\n🚀 Initializing database...")
    init_db()

    db = SessionLocal()

    try:
        # ---------------------------
        # CREATE ORGANIZATION
        # ---------------------------
        org = db.query(Organization).filter_by(name=ORG_NAME).first()

        if not org:
            org = Organization(name=ORG_NAME, billing_tier="enterprise")
            db.add(org)
            db.commit()
            db.refresh(org)
            print(f"✅ Created organization: {ORG_NAME}")
        else:
            print(f"ℹ️ Organization already exists: {ORG_NAME}")

        # ---------------------------
        # CREATE API KEY
        # ---------------------------
        raw_key = f"wf_live_{secrets.token_hex(16)}"
        key_hash = hash_api_key(raw_key)

        api_key = APIKey(
            key_hash=key_hash,
            organization_id=org.id
        )

        db.add(api_key)
        db.commit()

        print("\n🔑 API KEY (SAVE THIS):")
        print(raw_key)

        # ---------------------------
        # CREATE POLICY
        # ---------------------------
        policy = (
            db.query(Policy)
            .filter_by(
                organization_id=org.id,
                name=POLICY_NAME
            )
            .first()
        )

        if not policy:
            policy = Policy(
                organization_id=org.id,
                name=POLICY_NAME
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)
            print(f"\n✅ Created policy: {POLICY_NAME}")
        else:
            print(f"\nℹ️ Policy already exists: {POLICY_NAME}")

        # ---------------------------
        # CREATE POLICY VERSION (IMMUTABLE)
        # ---------------------------
        compiled_hash = hashlib.sha256(
            str(SAMPLE_POLICY).encode()
        ).hexdigest()

        version = PolicyVersion(
            policy_id=policy.id,
            version_number="1.0",
            raw_rules_json=SAMPLE_POLICY,
            compiled_hash=compiled_hash,
            created_at=datetime.utcnow()
        )

        db.add(version)
        db.commit()

        print("\n📜 Created Policy Version: v1.0")
        print(f"Hash: {compiled_hash[:12]}...")

        print("\n✅ SEED COMPLETE")
        print("You can now call /validate with this API key.")

    finally:
        db.close()


# ---------------------------
# ENTRY
# ---------------------------

if __name__ == "__main__":
    run()