# Issue #19 compiler and package acceptance

This draft stacks on issue #17 / PR #18 at
`54379d9c8044544fc1b8f32109bdfce35c1c6a05`. The original evidence in `../issue17`
and all retained fixtures are unchanged. Active development uses Compiler PR #8 at
`ae590dee058d3481e384dea850d5b7d980f533ff`, distribution 0.5.0, with no fallback.
Runtime metadata requires `>=0.5.0,<0.6.0`, never Git. No supplied compiler archive
was provided: acceptance retains a locally built pip-cached VCS wheel, its origin,
and SHA-256. Archive hashes can vary between builds; compiled outputs must match.

## Reproduction and evidence

Install `requirements-ci.txt` into a fresh Python 3.10 or 3.14 environment. From a
clean committed checkout, run (replace the head with the full commit being tested):

```text
python tools/run_action_policy_acceptance.py --expected-head FULL_40_CHARACTER_COMMIT --output runtime/issue19-acceptance
```

The output directory must be new. The same runner executes automatically on Linux
and Windows for PRs targeting main or `feat/issue-17-action-authority-dev`, main
pushes, and manual runs with a required full commit. Checkout and the runner compare
the actual tested head to the requested PR head/push/manual commit. Read-only
permissions and checkout without persisted credentials are used.

Each job retains `acceptance.json`, JUnit XML, skip reasons, per-suite installed
module paths, interpreter versions, pip install reports/freeze/check logs, compiler
PEP 610 provenance and installed Python file hashes, package metadata, fresh wheel
and sdist SHA-256 values, archives, and all command logs. Failures preserve their
exit status and upload partial evidence. Test/build dependencies are pinned in
`requirements-ci.txt`, including the Python 3.10 TOML backport; that constraint also
applies to nested build isolation. Resolved transitive versions are recorded.

Source and installed-wheel suites each run once with the opt-in absent and once
with `WAVEFRAME_LEDGER_ACTION_POLICY_DEV=1`. Default runs must skip exactly 44
explicit development cases. Environments without Guard must also skip exactly
three optional Guard entries (including one module collection skip). Native runs
must execute all 44 development cases; unexpected skips fail acceptance. The Guard
0.17.0 extra environment runs both suites with no optional Guard skips. Its legacy
allowed/blocked replay establishes only historical extra behavior.

The wheel is built from the fresh sdist and passes `twine check --strict`. Required
runtime modules, schemas, test fixtures, examples, tools, Python floor, runtime
compiler range, and unchanged Guard extra are checked. Installed tests run under
`python -I` from an extracted support tree containing **no Ledger source package**;
every loaded Ledger module must come from that environment. The complete suite
exercises existing CLI paths, and separate isolated API/CLI probes reproduce all
three full native chains, verify public receipts without compiler imports, run the
native v3 example, and invoke the installed entry point.

Candidate installations all resolve the supplied compiler using ordinary pip
resolution and `pip check`. An empty environment must reject a dry-run installation
of the Ledger wheel with Compiler 0.4.0 as `ResolutionImpossible`; installation or
network errors cannot count as this rejection. Independent published environments
remain pinned to Compiler 0.4.0, Guard 0.18.0 and Ledger 0.7.0/0.8.0. Both execute
the 24 real old-runtime rejection cases. The published 0.8 environment also checks
historical allowed modify, blocked unlisted modify, and blocked create. Its canonical
historical identities must match both the candidate and retained issue #17 evidence.
The retained raw issue #17 golden-file hashes describe a Windows CRLF checkout;
reports separately identify current checkout-byte and Git-blob hashes and verify
the retained CRLF hashes without rewriting any file or evidence. Canonical JSON
artifact hashes must be identical on both platforms.
No forced incompatible install or `--no-deps` install counts as compatibility.

New legacy compiler wrapper metadata may identify 0.5.0. No retained evidence,
hashed approved meaning, catalog identity, review, confirmation, approval, or
publication hash may change to accommodate it.

## Remaining gates

- The unchanged branch version is **unpublished development only**. These contents
  must never be published as another 0.8.0. Proposed Ledger **0.9.0** needs coordination.
- Compiler 0.5.0 merge/release/publication and final complete wheel-set acceptance.
- Guard native creation/runtime acceptance; joint metadata must address its Ledger
  `>=0.7.0,<0.9.0` constraint and compiler-0.4.0 test/dev pins, final package versions,
  ordinary `Ledger[guard]` installation and staged optional-cycle publication.
  Keep the legacy extra at 0.17.0; do not infer a future compatible range.
- Production catalog/approval transition: default catalog 1.0.0, immutable development
  catalog 2.0.0, development enforcement-point identity, review wording and opt-in
  stay unchanged. Existing approval does not approve a production catalog.
- Guard filesystem acceptance, downstream forged-legacy-envelope hardening, Cloud
  integration, customer acceptance and activation remain separate decisions.

Both PRs remain draft. No merge, tag, release, package publication, deployment or
activation is part of this work.
