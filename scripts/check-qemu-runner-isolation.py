#!/usr/bin/env python3
"""Refuse trusted QEMU jobs when the runner can see Windows drives."""

from pathlib import Path


def windows_drive_mounts(mounts: str) -> list[str]:
    visible = []
    for line in mounts.splitlines():
        fields = line.split()
        if len(fields) < 4:
            raise ValueError("invalid /proc/self/mounts row")
        _, target, filesystem, options = fields[:4]
        if filesystem.lower() == "drvfs" or (
            filesystem == "9p"
            and any(option.startswith("aname=drvfs") for option in options.split(","))
        ):
            visible.append(target)
    return visible


def main() -> int:
    mounts = windows_drive_mounts(Path("/proc/self/mounts").read_text(encoding="utf-8"))
    if mounts:
        print(
            "::error::Windows DrvFs mount visible to QEMU runner at "
            + ", ".join(mounts)
            + "; unmount it before running trusted guest code"
        )
        return 1
    if Path("/mnt/c/Users").exists():
        print("::error::Windows user directory visible to QEMU runner; unmount it first")
        return 1
    print("QEMU runner has no visible Windows drive mount")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
