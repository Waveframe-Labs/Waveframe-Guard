from waveframe_guard import Guard, __version__


def test_public_guard_export_is_sdk_facade():
    assert Guard.__name__ == "Guard"


def test_public_version_matches_release():
    assert __version__ == "0.10.0"
