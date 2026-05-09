import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from waveframe_guard import install_guard, guard, GovernanceError

# -------------------------
# Setup
# -------------------------

CONTRACT_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "finance-core-0.3.0.contract.json"
)

install_guard(
    actor={"id": "user-1", "type": "human", "role": "manager"},
    contract_path=CONTRACT_PATH
)


@guard
def test_action():
    return True


# -------------------------
# Benchmark
# -------------------------

N = 1000

start = time.perf_counter()

for _ in range(N):
    test_action()

end = time.perf_counter()

print(f"Executed {N} guarded calls in {end - start:.6f}s")
print(f"Avg per call: {(end - start) / N * 1000:.3f} ms")

install_guard(
    actor={"id": "user-1", "type": "human", "role": "intern"},
    contract_path=CONTRACT_PATH
)

blocked = 0

start = time.perf_counter()

for _ in range(N):
    try:
        test_action()
    except GovernanceError:
        blocked += 1

end = time.perf_counter()

print(f"Blocked {blocked}/{N} calls in {end - start:.6f}s")
