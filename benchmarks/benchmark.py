import time

from waveframe_guard import install_guard, guard, GovernanceError
from compiler.compile_policy import compile_policy

# -------------------------
# Setup
# -------------------------

policy = {
    "contract_id": "bench",
    "contract_version": "0.3.0",
    "authority": {
        "required_roles": ["manager"]
    }
}

compiled = compile_policy(policy)

install_guard(
    actor={"id": "user-1", "type": "human", "role": "manager"},
    contract=compiled
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
    contract=compiled
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
