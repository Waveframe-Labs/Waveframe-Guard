# Waveframe Guard v0.10.0 Release Notes

## Summary

v0.10.0 freezes the public developer path for Guard as a local execution-boundary SDK:
install the package, import `Guard` from `waveframe_guard`, wrap the action, and get an
allowed or blocked decision before execution.

This release also tightens package boundaries so Guard no longer relies on an ambiguous
bare `server` import when local runtime inspection helpers are needed.

## Highlights

- Added `Guard` as a top-level public export from `waveframe_guard`.
- Added `examples/quickstart_guard.py` as a runnable SDK quickstart.
- Reframed the README around the canonical SDK path and local allow/block behavior.
- Added `waveframe_guard.server.local_api` as the stable package-qualified local API boundary.
- Updated local API tests to import `from waveframe_guard.server import local_api`.
- Added a dependency-boundary regression test that rejects bare `server` imports.
- Clarified that Guard Inspector is a private operational visualization layer, not part of the public Guard SDK package and not the owner of enforcement semantics.
- Updated package metadata, citation metadata, security support, and public version exports to `0.10.0`.

## Scope Boundary

Guard evaluates runtime admissibility locally against compiled authority.
Guard never derives governance meaning from raw policy text.

Guard Inspector consumes Guard outcomes and artifacts for private operational inspection.
It is not shipped as part of the public Guard SDK package, does not author policy, and
does not own enforcement semantics.

## Verification

- `python -m pytest -q`: `108 passed`
- `python examples/quickstart_guard.py`: `executed=False`, `decision=blocked`
- `python -c "import waveframe_guard, importlib.metadata as m; print(waveframe_guard.__version__); print(m.version('waveframe-guard'))"`: `0.10.0`, `0.10.0`
