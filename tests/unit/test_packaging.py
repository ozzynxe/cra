"""Data files that must survive `pip install .`.

This exists because they did not. `cra/regulation/*.yaml` was missing from a
built wheel while every test passed, because the whole suite runs against an
editable install where the files are simply present on disk. The break would
first appear in the production image, at the first `classify_product` call.

These tests assert the packaging *declaration* rather than building a wheel —
cheap enough to run every time, and it catches the thing that actually goes
wrong: adding a new data directory and forgetting the pyproject entry.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "cra"


def _declared() -> dict[str, list[str]]:
    with (ROOT / "pyproject.toml").open("rb") as fh:
        cfg = tomllib.load(fh)
    return cfg["tool"]["setuptools"]["package-data"]


def test_every_package_holding_data_files_declares_them():
    """The general guard: find data directories, check each is declared.

    Deliberately derived from the tree rather than hardcoded, so a new
    catalogue added next year fails here instead of in production.
    """
    declared = _declared()
    for pattern, suffix in (("*.yaml", ".yaml"), ("*.css", ".css")):
        for path in SRC.rglob(pattern):
            package = "cra." + str(path.parent.relative_to(SRC)).replace("/", ".")
            assert package in declared, (
                f"{path.relative_to(ROOT)} would not ship: add "
                f'"{package}" = ["*{suffix}"] to [tool.setuptools.package-data]'
            )
            assert f"*{suffix}" in declared[package]


def test_the_catalogues_that_exist_today_are_declared():
    """Named explicitly as well, so deleting a file cannot quietly weaken the
    check above into vacuous truth."""
    declared = _declared()
    assert "cra.regulation" in declared
    assert "cra.report_templates" in declared
    for name in ("annex_i.yaml", "product_classes.yaml", "annex_vii.yaml"):
        assert (SRC / "regulation" / name).exists()
    assert (SRC / "report_templates" / "v1.yaml").exists()
