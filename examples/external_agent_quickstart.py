# ---
# title: "Waveframe Guard External Agent Quickstart"
# filetype: "python"
# type: "example"
# domain: "guard-sdk"
# version: "0.16.1"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Proprietary"
# ai_assisted: "partial"
# ---

from waveframe_guard.quickstarts.external_agent import (
    QuickstartSettings,
    build_guard,
    main,
    run_quickstart,
)

__all__ = ["QuickstartSettings", "build_guard", "main", "run_quickstart"]


if __name__ == "__main__":
    main()
