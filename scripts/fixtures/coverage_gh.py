import json
import os
from pathlib import Path
import sys


def main():
    args = sys.argv[1:]
    if args == [
        "api",
        "repos/omg-cli/omg/actions/runs/101/artifacts?per_page=100",
    ]:
        print(json.dumps({
            "total_count": 1,
            "artifacts": [{
                "id": 102,
                "name": "coverage-lcov",
                "expired": False,
                "workflow_run": {"id": 101, "head_sha": "a" * 40},
            }],
        }))
        return
    if len(args) == 9 and args[:8] == [
        "run", "download", "101", "--repo", "omg-cli/omg",
        "--name", "coverage-lcov", "--dir",
    ]:
        destination = Path(args[8])
        if not destination.is_dir():
            raise SystemExit("Missing destination")
        (destination / "lcov.info").write_bytes(
            b"SF:/fixture/src/shared.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"
        )
        if os.environ["COVERAGE_GH_EXTRA"] == "1":
            (destination / "unexpected.txt").write_bytes(b"unexpected\n")
        return
    raise SystemExit("Undeclared gh argv: " + repr(args))


if __name__ == "__main__":
    main()
