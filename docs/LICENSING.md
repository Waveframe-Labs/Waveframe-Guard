# Licensing scope

The Waveframe Guard Core SDK, repository-owned documentation, tests, fixtures,
and examples in this repository are licensed under [Apache License 2.0](../LICENSE).
Commercial use, modification, redistribution, and hosting of the Guard
Core SDK are permitted under Apache-2.0.
Keep the applicable license, attribution and modification notices when
redistributing. [NOTICE](../NOTICE) supplies the Waveframe Labs attribution
and adds no usage conditions. See [contribution terms](../CONTRIBUTING.md).

Apache-2.0 does not grant rights to Waveframe names, trademarks, service marks
or product names, except for reasonable origin identification and reproducing
NOTICE as stated in section 6. The externally hosted logo linked by the README
is not bundled in this repository or its distributions.

Waveframe Cloud, Console, hosted translation, managed evidence operations,
Guard Inspector, Ledger Workspace, enterprise identity/integrations, support,
and other separately distributed services/products are separate commercial
offerings and are not relicensed here. This distinction adds no restriction to
the SDK code included in this repository, including the Cloud client code.
An independent SDK distributor may offer competing products or paid support
under Apache-2.0; it does not need a Waveframe subscription to exercise those
license rights.

## Rights and provenance audit for issue #30

Audited base: `98ae9842233bafab0b80328f15f6da984a0d0acd`.
The rights basis is the existing Waveframe Labs copyright notice, the
single-author repository history, and the repository owner's instruction to
license the repository-owned material under Apache-2.0.

- Git history contains 348 commits attributed to Shawn C. Wright
  (`swright@waveframelabs.org`). GitHub lists `Wright-Shawn` as the sole
  contributor. GitHub also appears as a merge committer; no additional authors
  or coauthor trailers were found.
- The existing copyright attribution is `Copyright (c) 2026 Waveframe Labs`.
  File headers identify Waveframe Labs and, where present, AI assistance.
  No conflicting third-party ownership notices or contribution agreements were
  found in the tracked repository. The relicensing instruction covers this
  repository-owned material; no third-party component is silently relicensed.
- All 164 tracked files were inventoried. There are no vendored package trees,
  Git submodules, bundled binary assets, fonts or copied third-party license
  notices. The README references a separately hosted Waveframe branding image;
  the image bytes are not included in Guard's wheel or source distribution.
- The runtime adapters import upstream APIs rather than vendoring their source.
  OS bindings implement documented interfaces; the existing architecture guide
  retains its Windows/Linux API references. No copied implementation requiring
  a separate notice was identified.
- The finance examples and contracts are small repository-authored policies
  and generated fixtures. The Cloud publication fixture records synthetic
  `example.com` identities and Waveframe compiler provenance. Their introduction
  commits and generators were inspected; no external customer policy or private
  operational evidence was identified. Compiler/Ledger packages remain separate
  dependencies under their own licenses.

The audit found no unresolved third-party authorship or relicensing-rights
blocker in the repository-owned components at that base.

## Dependency licenses and attribution

The minimum/current installed distributions and their packaged license files
were inspected. Runtime dependency ranges are unchanged by issue #30.

| Package | Inspected versions | Declared license | Packaged notices |
| --- | --- | --- | --- |
| CRI-CORE | 0.13.0; exact 0.14.0 candidate `411dfaa976fd4b37efc5fd3e39076edcd3603e1b` | Apache-2.0 | LICENSE contains an Apache notice/link and `Copyright (c) 2025 Shawn C. Wright and contributors`; no NOTICE |
| Proposal Normalizer | 0.2.0 | Apache-2.0 | Full LICENSE; no NOTICE |
| Governance Ledger | 0.7.0, 0.8.0 | Apache-2.0 | Full LICENSE; no NOTICE |
| requests | 2.33.0, 2.34.2 | Apache-2.0 | LICENSE and NOTICE: `Requests`, `Copyright 2019 Kenneth Reitz` |
| Contract Compiler (test/dev only) | 0.4.0 | Apache-2.0 | Full LICENSE; no NOTICE |

These are separately resolved distributions, not copied into Guard's wheel or
sdist. Their licenses are compatible with the SDK's Apache-2.0 license. Guard's
minimal NOTICE therefore contains its own attribution only. A distributor that
bundles dependencies must retain those packages' licenses, copyright notices
and any NOTICE content, including requests' NOTICE; Guard's license does not
replace them. The CRI wheel uses an abbreviated Apache notice rather than a
full license copy; a combined distribution must include the complete Apache
license and preserve its attribution. No dependency source or notices are
modified by this change. Future dependency updates require a renewed audit.

## Packaging and release status

Package metadata uses `License-Expression: Apache-2.0` and `License-File` entries
for LICENSE and NOTICE. Both files are included under the wheel's
`.dist-info/licenses/` directory and at the sdist root, and installed-package
acceptance checks their contents. Regression tests also reject conflicting
SDK licensing text in repository documentation.

The requested legacy `License :: OSI Approved :: Apache Software License`
classifier cannot coexist with an SPDX license expression in the pinned
setuptools backend: it raises `InvalidConfigError`. The canonical SPDX field
is used; existing non-license classifiers remain unchanged. This follows
[PEP 639](https://peps.python.org/pep-0639/) and the
[setuptools packaging guidance](https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html).

This repository change is intended for the coordinated Guard 0.18.0
publication. Issue #30 remains open until that publication. Package version
and release date are unchanged, and existing published artifacts are not
retroactively replaced by this change.
