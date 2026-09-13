# Golden Path Published Authority Fixture

This fixture is the canonical Ledger v0.5.0 publication used by Waveframe's cross-repository Golden Path.

It was produced by the real Ledger approval and publication pipeline with fixed timestamps, then consumed unchanged by Guard v0.13.0 through the local registry resolver and evaluated as a blocked execution.

Identity:

- Authority: `finance-policy@1.0.0`
- Publication: `pub_20260717_0001`
- Contract schema: `compiled_authority_contract.v1`
- Contract hash: `sha256:c26887c13491fb5db61f46e3cc83a5769fd4071087e978e9de8db2e5ab20248a`
- Bundle hash: `sha256:7c2ec612a5a58f806a89ad245a63dbecda969bdaf4d06b4d2c04beaab0e229b7`

Consumers must treat the files under `contracts/` as immutable generated artifacts. Tests may copy this directory to a temporary workspace, but must not rewrite the bundle before passing it to Guard.
