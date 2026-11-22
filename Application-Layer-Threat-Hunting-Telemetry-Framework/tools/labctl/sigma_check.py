"""``labctl sigma-check``: lint Sigma rules; optionally convert with sigma-cli.

Conversion (Req 10.5) runs ``sigma convert -t opensearch_lucene`` per file when
``sigma-cli`` is installed. Sigma correlation rules (value_count / temporal) are
not convertible to a Lucene query by the opensearch_lucene backend; they are
skipped for conversion (documented, not a failure) because their thresholds are
implemented as OpenSearch monitors (see docs/detections.md).
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from labcommon.sigma_check import check_directory, is_correlation

REPO_ROOT = Path(__file__).resolve().parents[2]
SIGMA_DIR = REPO_ROOT / "detections" / "sigma"


def _convert(directory: Path, names: list[str]) -> list[str]:
    """Convert detection (non-correlation) rules; return failure messages."""
    failures: list[str] = []
    for name in names:
        docs = [d for d in yaml.safe_load_all((directory / name).read_text("utf-8")) if d]
        plain = [d for d in docs if not is_correlation(d)]
        skipped = len(docs) - len(plain)
        if skipped:
            print(f"  {name}: skipping {skipped} correlation rule(s) (not convertible)")
        if not plain:
            continue
        with tempfile.TemporaryDirectory() as tmp:
            tmpfile = Path(tmp) / name
            tmpfile.write_text(yaml.safe_dump_all(plain, sort_keys=False), encoding="utf-8")
            proc = subprocess.run(
                ["sigma", "convert", "-t", "opensearch_lucene", "--without-pipeline", str(tmpfile)],
                capture_output=True, text=True,
            )
        if proc.returncode != 0:
            failures.append(f"{name}: {(proc.stderr or proc.stdout).strip().splitlines()[-1:]}")
    return failures


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="labctl sigma-check")
    ap.add_argument("--dir", default=str(SIGMA_DIR), help="Sigma rule directory")
    ap.add_argument("--no-convert", action="store_true", help="skip sigma-cli conversion")
    args = ap.parse_args(argv)

    directory = Path(args.dir)
    result = check_directory(directory)
    for name in result.valid_files:
        print(f"OK       {name}")
    for rej in result.rejected:
        print(f"REJECTED {rej}", file=sys.stderr)
    status = 0 if result.ok else 1

    if not args.no_convert:
        if shutil.which("sigma"):
            failures = _convert(directory, result.valid_files)
            for f in failures:
                print(f"CONVERT-FAIL {f}", file=sys.stderr)
            if failures:
                status = 1
        else:
            print("sigma-cli not installed; skipping conversion (pip install sigma-cli)")
    return status


if __name__ == "__main__":
    sys.exit(main())
