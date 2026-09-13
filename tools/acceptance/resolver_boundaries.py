"""Ordinary pip rejection using the actual Guard wheel and exact candidates.

Behavioral compatibility is established by installed acceptance, never synthetic
package metadata. No dependency-resolution bypass is used.
"""
import argparse
from pathlib import Path
import subprocess
import sys


def check(wheel: Path, *, historical: bool = False) -> None:
    if historical:
        raise ValueError("Use Ledger's independent published historical acceptance")
    requirements = Path(__file__).resolve().parents[2] / ".github/requirements/action-policy-release.txt"
    for spec in ("governance-ledger==0.7.0", "governance-ledger==0.8.0"):
        result = subprocess.run([sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed",
                                 str(wheel.resolve()), "-r", str(requirements), spec],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert result.returncode != 0 and "ResolutionImpossible" in result.stdout, result.stdout
        print(f"Actual wheel resolver rejected {spec}:\n{result.stdout}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    args = parser.parse_args()
    check(args.wheel)
