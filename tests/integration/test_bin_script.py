import subprocess
from pathlib import Path


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
    assert result.stdout.startswith("gruff-py 0.1.0-dev")
    assert "Available commands:" in result.stdout
