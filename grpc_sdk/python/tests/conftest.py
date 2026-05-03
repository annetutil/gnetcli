from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple

import pytest


@pytest.fixture(scope="session")
def repo_root() -> Path:
    root = Path(__file__).resolve().parent.parent.parent.parent
    if root is None:
        pytest.fail("go.mod not found; run tests inside gnetcli checkout")
    return root


@pytest.fixture(scope="session")
def go_binaries(repo_root: Path, tmp_path_factory: pytest.TempPathFactory) -> Tuple[str, str]:
    if shutil.which("go") is None:
        pytest.fail("go not on PATH (needed to build gnetcli_server and gswitch)")

    pre = os.environ.get("GNETCLI_TEST_PREBUILT_DIR")
    if pre:
        base = Path(pre)
        return str(base / "gnetcli_server"), str(base / "gswitch")

    base = tmp_path_factory.mktemp("go_bins")
    server = base / "gnetcli_server"
    gsw = base / "gswitch"
    subprocess.run(
        ["go", "build", "-o", str(server), "./cmd/gnetcli_server"],
        cwd=repo_root,
        check=True,
    )
    subprocess.run(
        ["go", "build", "-o", str(gsw), "./cmd/gswitch"],
        cwd=repo_root,
        check=True,
    )
    return str(server), str(gsw)
