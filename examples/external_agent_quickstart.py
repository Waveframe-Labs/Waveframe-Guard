# ---
# title: "Waveframe Guard External Agent Quickstart"
# filetype: "python"
# type: "example"
# domain: "guard-sdk"
# version: "0.17.0"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Apache-2.0"
# ai_assisted: "partial"
# ---

"""Guard enforces actions that pass through its wrapped tool boundary. Actions
that reach the same capability through another function, tool, process,
credential, or API path are outside that enforcement guarantee.

This entrypoint runs run_quickstart's allocate_budget example. Its @guard.tool
wrapper evaluates immediately before mutations.append(mutation) in that
callback. It protects this callable path, not the machine or repository globally.
See the packaged module docstring for the canonical threat-model link.
"""
from waveframe_guard.quickstarts.external_agent import (
    QuickstartSettings,
    build_guard,
    main,
    run_quickstart,
)

__all__ = ["QuickstartSettings", "build_guard", "main", "run_quickstart"]


if __name__ == "__main__":
    main()
