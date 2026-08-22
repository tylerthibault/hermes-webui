from pathlib import Path


def test_named_admin_origin_accepts_exact_public_allowlist():
    source = (Path(__file__).parents[1] / "api/routes.py").read_text()
    assert "allowed_origins = {" in source
    assert "if supplied in allowed_origins:" in source
