import time
import uuid

from proposal_normalizer.build_proposal import build_proposal
from cricore.interface.evaluate_proposal import evaluate_proposal
from waveframe_guard.core import run_validation


# ---------------------------
# TEST DATA
# ---------------------------

contract = {
    "contract_id": "bench-policy",
    "contract_version": "1.0.0",
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
        {"type": "separation_of_duties", "roles": ["responsible", "accountable"]}
    ]
}

action = {
    "type": "transfer",
    "amount": 5000,
    "system": "finance",
    "resource": "budget"
}

actor = "ai-agent"
context = {}


def build_test_proposal():
    return build_proposal(
        proposal_id=str(uuid.uuid4()),
        actor={"id": actor, "type": "agent"},
        artifact_paths=[],
        mutation={
            "domain": action["system"],
            "resource": action["resource"],
            "action": action["type"],
        },
        contract={
            "id": contract["contract_id"],
            "version": contract["contract_version"],
            "hash": "test",
        },
        run_context={
            "identities": {
                "actors": [
                    {"id": actor, "type": "agent", "role": "proposer"},
                    {"id": "user1", "type": "human", "role": "responsible"},
                    {"id": "user2", "type": "human", "role": "accountable"},
                ],
                "required_roles": ["proposer", "responsible", "accountable"],
                "conflict_flags": {},
            },
            "integrity": {"artifacts_present": True},
            "publication": {"ready": True},
        },
    )


# ---------------------------
# BENCHMARKS
# ---------------------------

def benchmark_kernel(runs=1000):
    proposal = build_test_proposal()

    start = time.perf_counter()

    for _ in range(runs):
        evaluate_proposal(proposal, contract)

    end = time.perf_counter()

    avg_ms = (end - start) / runs * 1000
    print(f"Kernel avg: {avg_ms:.4f} ms over {runs} runs")
    return avg_ms


def benchmark_kernel_single():
    proposal = build_test_proposal()

    start = time.perf_counter()
    evaluate_proposal(proposal, contract)
    end = time.perf_counter()

    print(f"Single run: {(end - start)*1000:.4f} ms")


def benchmark_proposal_build(runs=1000):
    start = time.perf_counter()

    for _ in range(runs):
        build_test_proposal()

    end = time.perf_counter()

    avg_ms = (end - start) / runs * 1000
    print(f"Proposal build avg: {avg_ms:.4f} ms")
    return avg_ms


def benchmark_compiler(runs=100):
    from compiler.compile_policy_file import compile_policy_file

    start = time.perf_counter()

    for _ in range(runs):
        compile_policy_file("finance-policy.json")

    end = time.perf_counter()

    avg_ms = (end - start) / runs * 1000
    print(f"Compiler avg: {avg_ms:.4f} ms")


def benchmark_full_pipeline(runs=1000):
    start = time.perf_counter()

    for _ in range(runs):
        run_validation(contract, action, actor, context)

    end = time.perf_counter()

    avg_ms = (end - start) / runs * 1000
    print(f"Full pipeline avg: {avg_ms:.4f} ms")
    return avg_ms


# ---------------------------
# RUN
# ---------------------------

if __name__ == "__main__":
    print("\n--- Waveframe Guard Benchmark ---\n")

    k = benchmark_kernel()
    p = benchmark_proposal_build()
    f = benchmark_full_pipeline()

    print("\n--- Summary ---")
    print(f"Kernel: {k:.4f} ms")
    print(f"Proposal build: {p:.4f} ms")
    print(f"Full pipeline: {f:.4f} ms")
