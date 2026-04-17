# ---------------------------
# SEED SCRIPT — WAVEFRAME GUARD (FIXED)
# ---------------------------

import secrets
import json

from db import (
    SessionLocal,
    init_db,
    Organization,
    APIKey,
    Policy,
    PolicyVersion,
)

ORG_NAME = "Acme Corp"
POLICY_NAME = "finance-core"

SAMPLE_POLICY = {
    "contract_id": "finance-core",
    "contract_version": "1.0.0",
    "roles": {
        "required": ["proposer", "accountable"]
    },
    "constraints": [
        {
            "type": "separation_of_duties",
            "roles": ["proposer", "accountable"]
        }
    ]
}

def run():
    print("\n🚀 Initializing database...")
    init_db()

    db = SessionLocal()

    try:
        # ORG
        org = db.query(Organization).filter_by(name=ORG_NAME).first()

        if not org:
            org = Organization(name=ORG_NAME)
            db.add(org)
            db.commit()
            db.refresh(org)
            print(f"✅ Created org: {ORG_NAME}")
        else:
            print(f"ℹ️ Org exists: {ORG_NAME}")

        # API KEY
        raw_key = f"wf_live_{secrets.token_hex(16)}"

        api_key = APIKey(
            key_value=raw_key,
            organization_id=org.id
        )

        db.add(api_key)
        db.commit()

        print("\n🔑 API KEY:")
        print(raw_key)

        # POLICY
        policy = db.query(Policy).filter_by(
            organization_id=org.id,
            name=POLICY_NAME
        ).first()

        if not policy:
            policy = Policy(
                name=POLICY_NAME,
                organization_id=org.id
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)

        # POLICY VERSION
        version = PolicyVersion(
            policy_id=policy.id,
            version="1.0.0",
            rules_json=json.dumps(SAMPLE_POLICY)
        )

        db.add(version)
        db.commit()

        print("\n📜 Policy v1 created")
        print("\n✅ SEED COMPLETE")

    finally:
        db.close()


if __name__ == "__main__":
    run()