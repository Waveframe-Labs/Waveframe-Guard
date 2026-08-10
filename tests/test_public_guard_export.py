# ---
# title: "Guard Public Export Regression Test"
# filetype: "python"
# type: "test"
# domain: "guard-sdk"
# version: "0.14.0"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Proprietary"
# ai_assisted: "partial"
# ---

from waveframe_guard import Guard, __version__


def test_public_guard_export_is_sdk_facade():
    assert Guard.__name__ == "Guard"


def test_public_version_matches_release():
    assert __version__ == "0.14.0"
