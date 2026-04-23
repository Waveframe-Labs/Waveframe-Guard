# ---------------------------
# SEED SCRIPT — WAVEFRAME GUARD (DETERMINISTIC)
# ---------------------------

import json
from backend.db import (
    SessionLocal,
    init_db,
    Organization,
    APIKey,
    Policy,
    PolicyVersion,
)

ORG_ID = "org_demo_001"
API_KEY_VALUE = "wf_test_key_123"
POLICY_ID = "demo_policy_1"

SAMPLE_COMPILED_CONTRACT = {
    "contract_id": "finance-core",
    "contract_version": "1.2.0",
    "authority_requirements": {
        "required_roles": ["proposer", "responsible", "accountable"]
    },
    "artifact_requirements": {
        "artifacts_present": True
    },
    "stage_requirements": {
        "integrity": {"artifacts_present": True},
        "publication": {"ready": True}
    },
    "invariants": [
        {
            "type": "separation_of_duties",
            "roles": ["responsible", "accountable"]
        }
    ]
}


def run():
    print("\n🚀 Initializing database...")
    init_db()

    db = SessionLocal()

    try:
        # ---------------------------
        # ORG
        # ---------------------------
        org = db.query(Organization).filter_by(id=ORG_ID).first()

        if not org:
            org = Organization(
                id=ORG_ID,
                name="Demo Org"
            )
            db.add(org)
            db.commit()
            print("✅ Created org")
        else:
            print("ℹ️ Org exists")

        # ---------------------------
        # API KEY (FIXED VALUE)
        # ---------------------------
        existing_key = db.query(APIKey).filter_by(key_value=API_KEY_VALUE).first()

        if not existing_key:
            api_key = APIKey(
                key_value=API_KEY_VALUE,
                organization_id=ORG_ID
            )
            db.add(api_key)
            db.commit()
            print("✅ API key created:", API_KEY_VALUE)
        else:
            print("ℹ️ API key exists:", API_KEY_VALUE)

        # ---------------------------
        # POLICY (FIXED ID)
        # ---------------------------
        policy = db.query(Policy).filter_by(id=POLICY_ID).first()

        if not policy:
            policy = Policy(
                id=POLICY_ID,
                name="finance-core",
                organization_id=ORG_ID
            )
            db.add(policy)
            db.commit()
            print("✅ Policy created:", POLICY_ID)
        else:
            print("ℹ️ Policy exists:", POLICY_ID)

        # ---------------------------
        # POLICY VERSION
        # ---------------------------
        if not policy.versions:
            version = PolicyVersion(
                policy_id=policy.id,
                version="1.2.0",
                compiled_contract_json=json.dumps(SAMPLE_COMPILED_CONTRACT)
            )
            db.add(version)
            db.commit()
            print("✅ Policy version created")
        else:
            print("ℹ️ Policy version exists")

        print("\n🎯 SEED COMPLETE")

    finally:
        db.close()


if __name__ == "__main__":
    run()
