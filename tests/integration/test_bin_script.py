import subprocess
from pathlib import Path

from gruffpy.version import VERSION


def test_bin_gruff_py_launches_current_package() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [str(repo_root / "bin" / "gruff-py"), "--help"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith(f"gruff-py {VERSION}")
    assert "Available commands:" in result.stdout
