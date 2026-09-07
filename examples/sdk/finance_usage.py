"""Legacy migration example; see docs/getting-started/STRICT_EXECUTION_MIGRATION.md.

Guard execution is never advisory. Local/cloud selects authority resolution.
For a working supported tool example, run examples/quickstart_guard.py.
"""

from waveframe_guard import LegacyExecutionError, guard


@guard
def legacy_action():
    raise AssertionError("Legacy callbacks must never run")


if __name__ == "__main__":
    try:
        legacy_action()
    except LegacyExecutionError as exc:
        print(exc)
