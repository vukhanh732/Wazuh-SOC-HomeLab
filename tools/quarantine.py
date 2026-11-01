#!/usr/bin/env python3
"""Constrained Linux Wazuh Active Response for a VirusTotal-positive file."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys
from uuid import uuid4


class ResponseError(ValueError):
    pass


def candidate_path(message):
    if not isinstance(message, dict) or message.get("command") != "add":
        raise ResponseError("Only a stateless add command is supported")
    try:
        alert = message["parameters"]["alert"]
        rule_id = str(alert["rule"]["id"])
        source = alert["data"]["virustotal"]["source"]["file"]
    except (KeyError, TypeError) as exc:
        raise ResponseError("Missing VirusTotal alert fields") from exc
    if rule_id != "87105":
        raise ResponseError("Unexpected rule ID")
    if not isinstance(source, str) or not source or "\x00" in source:
        raise ResponseError("Invalid source path")
    return Path(source)


def quarantine(message, watch_dir, quarantine_dir, execute=False):
    source = candidate_path(message)
    watch = Path(watch_dir)
    destination = Path(quarantine_dir)
    if not watch.is_absolute() or not destination.is_absolute() or watch == destination:
        raise ResponseError("Watch and quarantine directories must be distinct absolute paths")
    if not source.is_absolute() or source.parent != watch or source.name in ("", ".", ".."):
        raise ResponseError("Source must be a direct child of the watch directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        watch_fd = os.open(watch, flags)
        try:
            dest_fd = os.open(destination, flags)
            try:
                info = os.stat(source.name, dir_fd=watch_fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise ResponseError("Source is not a regular file")
                if not execute:
                    return {"status": "dry-run", "source": str(source)}
                target_name = f"{source.name}.{uuid4().hex}.quarantine"
                # Hard-link creation is exclusive: an existing destination is never replaced.
                # The directories must be on the same filesystem. If unlink fails, the
                # original remains and the duplicate can be inspected safely.
                os.link(source.name, target_name, src_dir_fd=watch_fd, dst_dir_fd=dest_fd, follow_symlinks=False)
                moved = os.stat(target_name, dir_fd=dest_fd, follow_symlinks=False)
                if not stat.S_ISREG(moved.st_mode) or moved.st_ino != info.st_ino or moved.st_dev != info.st_dev:
                    os.unlink(target_name, dir_fd=dest_fd)
                    raise ResponseError("Source changed during quarantine; inspect destination")
                current = os.stat(source.name, dir_fd=watch_fd, follow_symlinks=False)
                if current.st_ino != moved.st_ino or current.st_dev != moved.st_dev:
                    os.unlink(target_name, dir_fd=dest_fd)
                    raise ResponseError("Source changed during quarantine")
                os.unlink(source.name, dir_fd=watch_fd)
                return {"status": "quarantined", "source": str(source), "destination": str(destination / target_name)}
            finally:
                os.close(dest_fd)
        finally:
            os.close(watch_fd)
    except OSError as exc:
        raise ResponseError(f"Filesystem operation failed: {exc.strerror}") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch-dir", required=True, type=Path)
    parser.add_argument("--quarantine-dir", required=True, type=Path)
    parser.add_argument("--execute", action="store_true", help="Move a file; default is a dry run")
    args = parser.parse_args(argv)
    try:
        line = sys.stdin.readline(1024 * 1024 + 1)
        if len(line) > 1024 * 1024:
            raise ResponseError("Active Response message exceeds 1 MiB")
        message = json.loads(line)
        result = quarantine(message, args.watch_dir, args.quarantine_dir, args.execute)
    except (json.JSONDecodeError, ResponseError) as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
