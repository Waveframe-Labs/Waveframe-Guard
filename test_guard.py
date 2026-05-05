from waveframe_guard import install_guard, guard
from compiler.compile_policy import compile_policy


policy = {
    "contract_id": "finance-core",
    "contract_version": "1.2.0",
    "authority": {"required_roles": ["manager"]},
}
compiled = compile_policy(policy)

install_guard(
    actor={"id": "u1", "type": "human", "role": "manager"},
    contract=compiled,
)


@guard
def test():
    return "executed"


print(test())
