from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = REPO_ROOT / "ui"


def test_guard_repo_does_not_require_private_inspector_ui_entrypoint():
    """Guard is the public SDK/runtime package; Inspector UI lives separately."""
    assert not (UI_ROOT / "index.html").exists()


def test_guard_repo_does_not_ship_private_inspector_runtime_surface():
    """Prevent proprietary Inspector screens from drifting back into Guard."""
    if not UI_ROOT.exists():
        return

    text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in UI_ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in {".html", ".js", ".css"}
    )

    private_inspector_terms = [
        "Guard Evaluation Inspector",
        "Persistent Organizational Runtime",
        "Local runtime control plane",
        "Active continuation leases",
        "Escalation queue",
        "Replay failures",
        "Invalidated continuations",
        "Runtime drift alerts",
        "Receipt browser",
        "Multi-run comparison",
    ]

    for term in private_inspector_terms:
        assert term not in text


def test_guard_public_docs_point_to_sdk_not_bundled_ui():
    """The public repo should sell the SDK path, not require a bundled UI."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert "from waveframe_guard import Guard" in readme
    assert "Guard Inspector" in readme
    assert "public Guard SDK package" in readme
    assert "enforcement semantics" in readme
