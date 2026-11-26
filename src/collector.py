#!/usr/bin/env python3
"""
JSONL log collector for SATUSEHAT FHIR Monitor TUI.
Tails the daily rotating files (`fhir-YYYY-MM-DD.jsonl`) written by `proxy.py`.
Reading never modifies logs, queries a database, or calls SATUSEHAT APIs, so several admins can
watch the same logs over SSH. The only write operation is the explicit `delete_logs()` (TUI `D` key /
`--clear-logs`). Lines longer than MAX_LINE_BYTES are skipped.

Python 3.10+ (stdlib only).
"""

import datetime
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


MAX_LINE_BYTES = 16 * 1024 * 1024


def json_loads_safe(s: str) -> Any:
    if len(s) > MAX_LINE_BYTES:
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


class TransactionCollector:
    """Thread-safe tailer for SATUSEHAT proxy JSONL logs (read-only except delete_logs)."""

    def __init__(
        self,
        config: Dict[str, Any],
        base_dir: str,
        log_dir: Optional[str] = None,
        single_file: Optional[str] = None,
        days: int = 1,
    ) -> None:
        self.config = config
        self.base_dir = base_dir
        self.days = max(1, int(days))
        self.max_items: int = int(config.get("max_stored_transactions", 2000))

        self.single_file: Optional[str] = (
            os.path.abspath(single_file) if single_file else None
        )

        raw_log_dir = (
            log_dir
            or os.environ.get("SATUSEHAT_LOG_DIR")
            or config.get("log_dir")
            or "logs"
        )
        if os.path.isabs(str(raw_log_dir)):
            self.log_dir = str(raw_log_dir)
        else:
            self.log_dir = os.path.join(base_dir, str(raw_log_dir))

        self._lock = threading.RLock()
        # Stored newest-first at index 0 for display
        self._items: List[Dict[str, Any]] = []
        self._by_id: Dict[str, Dict[str, Any]] = {}
        self._version: int = 0

        self._stop_event = threading.Event()
        self._active_file: Optional[str] = None
        self._active_inode: Optional[int] = None
        self._active_offset: int = 0

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    @property
    def source_label(self) -> str:
        if self.single_file:
            return self.single_file
        return self._today_file_path()

    def _today_file_path(self) -> str:
        day = datetime.date.today().isoformat()
        return os.path.join(self.log_dir, f"fhir-{day}.jsonl")

    def _candidate_files(self) -> List[str]:
        if self.single_file:
            return [self.single_file]
        today = datetime.date.today()
        files: List[str] = []
        for offset in range(self.days - 1, -1, -1):
            d = (today - datetime.timedelta(days=offset)).isoformat()
            p = os.path.join(self.log_dir, f"fhir-{d}.jsonl")
            if os.path.isfile(p):
                files.append(p)
        return files

    def get_snapshot(self) -> List[Dict[str, Any]]:
        """Return a shallow copy of transactions ordered newest-first."""
        with self._lock:
            return list(self._items)

    def load_initial(self) -> int:
        """Load recent JSONL log files read-only into memory."""
        loaded_files = self._candidate_files()
        target_tail = self.single_file or self._today_file_path()

        with self._lock:
            self._items.clear()
            self._by_id.clear()
            self._active_file = target_tail
            self._active_inode = None
            self._active_offset = 0

        for path in loaded_files:
            if not os.path.isfile(path):
                continue
            try:
                st = os.stat(path)
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        rec = json_loads_safe(line)
                        if isinstance(rec, dict) and rec.get("id"):
                            self._upsert_item(rec)
                    end_pos = f.tell()
                if os.path.abspath(path) == os.path.abspath(target_tail):
                    with self._lock:
                        self._active_inode = st.st_ino
                        self._active_offset = end_pos
            except OSError:
                continue

        with self._lock:
            self._version += 1
            return len(self._items)

    def reload_now(self) -> int:
        """Re-read JSONL log files from disk on user demand."""
        return self.load_initial()

    def clear_view(self) -> None:
        """Clear in-memory items without deleting log files on disk."""
        with self._lock:
            self._items.clear()
            self._by_id.clear()
            self._version += 1

    def delete_logs(self, delete_all: bool = False) -> Tuple[bool, str]:
        """Delete today's or all fhir-*.jsonl log files from disk and clear memory."""
        targets: List[str] = []
        try:
            if self.single_file:
                if os.path.isfile(self.single_file):
                    targets.append(self.single_file)
            elif delete_all:
                if os.path.isdir(self.log_dir):
                    for name in sorted(os.listdir(self.log_dir)):
                        if name.startswith("fhir-") and name.endswith(".jsonl"):
                            p = os.path.join(self.log_dir, name)
                            if os.path.isfile(p):
                                targets.append(p)
            else:
                today_path = self._today_file_path()
                if os.path.isfile(today_path):
                    targets.append(today_path)

            removed = 0
            for path in targets:
                os.remove(path)
                removed += 1
        except OSError as e:
            return False, f"Gagal hapus log: {e}"

        with self._lock:
            self._items.clear()
            self._by_id.clear()
            self._active_inode = None
            self._active_offset = 0
            self._version += 1

        return True, f"Berhasil hapus {removed} file log"

    def start_background_workers(self) -> None:
        """Start daemon thread for live read-only JSONL tailing."""
        t_tail = threading.Thread(target=self._tail_loop, name="JsonlTailer", daemon=True)
        t_tail.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _upsert_item(self, rec: Dict[str, Any]) -> None:
        rec_id = str(rec.get("id") or "")
        if not rec_id:
            return

        with self._lock:
            existing = self._by_id.get(rec_id)
            if existing:
                existing.update(rec)
            else:
                self._by_id[rec_id] = rec
                self._items.insert(0, rec)

            self._items.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
            if len(self._items) > self.max_items:
                for removed in self._items[self.max_items :]:
                    self._by_id.pop(str(removed.get("id")), None)
                self._items = self._items[: self.max_items]
            self._version += 1

    def _tail_loop(self) -> None:
        """Continuously tail active JSONL file (auto-switches on date rollover)."""
        while not self._stop_event.is_set():
            target = self.single_file or self._today_file_path()

            if self._active_file != target:
                self._active_file = target
                self._active_inode = None
                self._active_offset = 0

            if os.path.isfile(target):
                try:
                    st = os.stat(target)
                    if self._active_inode != st.st_ino or st.st_size < self._active_offset:
                        self._active_inode = st.st_ino
                        self._active_offset = 0

                    if st.st_size > self._active_offset:
                        with open(target, "r", encoding="utf-8", errors="ignore") as f:
                            f.seek(self._active_offset)
                            chunk = f.read()
                            # Only advance offset up to last complete newline to avoid partial lines
                            last_nl = chunk.rfind("\n")
                            if last_nl != -1:
                                complete_text = chunk[: last_nl + 1]
                                self._active_offset += len(complete_text.encode("utf-8"))
                                for raw_line in complete_text.splitlines():
                                    raw_line = raw_line.strip()
                                    if not raw_line:
                                        continue
                                    rec = json_loads_safe(raw_line)
                                    if isinstance(rec, dict) and rec.get("id"):
                                        self._upsert_item(rec)
                except OSError:
                    pass

            time.sleep(0.2)
