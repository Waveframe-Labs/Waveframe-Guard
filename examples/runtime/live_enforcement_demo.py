from pathlib import Path

from waveframe_guard import install_guard, guard
import os
import time

# -------------------------
# 1. Use published contract
# -------------------------

CONTRACT_PATH = (
    Path(__file__).resolve().parents[2]
    / "contracts"
    / "finance-policy-1.0.0.contract.json"
)

# -------------------------
# 2. Install Guard
# -------------------------

install_guard(
    actor={"id": "user-1", "type": "human", "role": "intern"},
    contract_path=CONTRACT_PATH,
    fail_mode="cache"
)

# -------------------------
# 3. Define action
# -------------------------

@guard
def transfer(amount):
    print(f"Transferred ${amount}")

# -------------------------
# 4. Run (Allowed? Blocked?)
# -------------------------

print("\n--- Attempt 1 (intern) ---")
try:
    transfer(100)
except Exception as e:
    print("BLOCKED:", e)

# -------------------------
# 5. Elevate role
# -------------------------

install_guard(
    actor={"id": "user-1", "type": "human", "role": "manager"},
    contract_path=CONTRACT_PATH
)

print("\n--- Attempt 2 (manager) ---")
transfer(100)

print("\n--- Simulate Cloud outage ---")
# Force offline mode by making the cached policy expire immediately and
# pointing the Cloud URL at a closed local port.
os.environ["WAVEFRAME_GUARD_URL"] = "http://127.0.0.1:9"

install_guard(
    actor={"id": "user-1", "type": "human", "role": "manager"},
    contract_path=CONTRACT_PATH,
    api_key="wf_demo_key",
    mode="cloud",
    fail_mode="cache",
    policy_refresh=0
)

time.sleep(0.1)
transfer(100)
