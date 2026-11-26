#!/usr/bin/env python3
"""
Entrypoint for SATUSEHAT FHIR Monitor TUI.

Viewer for the daily JSONL logs written by `proxy.py`. It never contacts SATUSEHAT or any database.
It only changes data on disk when YOU ask it to: deleting logs (`D` key / `--clear-logs`) or the
clipboard fallback file under a private per-user directory (removed again on exit).

Python 3.10+ (stdlib only).
"""

import sys

if sys.version_info < (3, 10):  # pragma: no cover
    sys.exit("satusehat-monitor requires Python 3.10 or newer.")

import argparse
import curses
import json
import os
from typing import Any, Dict

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SRC_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from collector import TransactionCollector
from tui import SatuSehatTUI, render_static_preview


def load_config() -> Dict[str, Any]:
    cfg_path = os.path.join(BASE_DIR, "config.json")
    if os.path.isfile(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except (OSError, ValueError):
            sys.stderr.write("WARNING: config.json unreadable/invalid; using defaults.\n")
    return {}


def main() -> int:
    ap = argparse.ArgumentParser(description="SATUSEHAT FHIR Monitor TUI (Read-Only)")
    ap.add_argument(
        "--log-dir",
        default=None,
        help="Directory containing daily fhir-YYYY-MM-DD.jsonl logs",
    )
    ap.add_argument(
        "--file",
        default=None,
        help="Specific JSONL file to tail read-only",
    )
    ap.add_argument(
        "--days",
        type=int,
        default=1,
        help="Number of recent days of JSONL logs to load on startup (default: 1)",
    )
    ap.add_argument(
        "--only-failed",
        action="store_true",
        help="Start with filter set to Gagal (errors/rejections only)",
    )
    ap.add_argument(
        "--clear-logs",
        action="store_true",
        help="Hapus semua file log JSONL di log-dir lalu keluar",
    )
    ap.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt for --clear-logs",
    )
    ap.add_argument(
        "--preview",
        action="store_true",
        help="Render a static text preview of the TUI table and exit",
    )
    ap.add_argument(
        "--mode",
        type=int,
        choices=[1, 2, 3, 4],
        default=1,
        help="Initial UI mode: 1=Split, 2=Table, 3=Inspect, 4=Summary",
    )
    args = ap.parse_args()

    config = load_config()
    collector = TransactionCollector(
        config=config,
        base_dir=BASE_DIR,
        log_dir=args.log_dir,
        single_file=args.file,
        days=args.days,
    )

    if args.clear_logs:
        if not args.yes:
            if not sys.stdin.isatty():
                print("Refusing to delete logs non-interactively; re-run with --yes to confirm.")
                return 1
            if input(f"Delete ALL fhir-*.jsonl files in {collector.log_dir}? [y/N] ").strip().lower() != "y":
                print("Cancelled.")
                return 1
        ok, msg = collector.delete_logs(delete_all=True)
        print(msg)
        return 0 if ok else 1

    collector.load_initial()

    initial_status = "Gagal" if args.only_failed else "ALL"

    if args.preview or not sys.stdout.isatty():
        try:
            print(
                render_static_preview(
                    collector,
                    mode=args.mode,
                    initial_status_filter=initial_status,
                )
            )
            sys.stdout.flush()
        except BrokenPipeError:
            # reader (e.g. `| head`) closed the pipe early: exit quietly
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0

    collector.start_background_workers()
    app = SatuSehatTUI(
        collector=collector,
        base_dir=BASE_DIR,
        initial_status_filter=initial_status,
    )
    app.mode = args.mode

    try:
        curses.wrapper(app.run)
    except KeyboardInterrupt:
        pass
    finally:
        collector.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
