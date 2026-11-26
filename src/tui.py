#!/usr/bin/env python3
"""
Clean Minimalist SATUSEHAT FHIR Monitor TUI (Claude Code / OpenCode style).
- Zero emojis, zero clutter ([LIVE]/env/org removed from header)
- Rounded Unicode box-drawing borders (╭─╮│╰─╯)
- 9 Columns including ENCOUNTER ID and PATIENT ID
- 4 View Modes:
    [1] Split View (Table + Dual Request/Response JSON)
    [2] Full Table View
    [3] Full Inspector View (Full IDs + Request/Response/cURL tabs)
    [4] Summary View (Ringkasan Transaksi FHIR per Resource)
"""

import atexit
import base64
import curses
import json
import os
import re
import shlex
import signal
import stat
import subprocess  # nosec B404
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from collector import TransactionCollector


# Color pair constants
CP_DEFAULT = 1
CP_HEADER = 2
CP_BORDER = 3
CP_SUCCESS = 4
CP_FAIL = 5
CP_METHOD_POST = 6
CP_METHOD_PUT = 7
CP_METHOD_GET = 8
CP_DIM = 9
CP_SELECTED = 10
CP_JSON_KEY = 11
CP_JSON_STR = 12
CP_JSON_NUM = 13
CP_ACCENT = 14


_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize_display(text: str) -> str:
    """Replace terminal control characters so log content can never inject escape sequences."""
    return _CTRL_RE.sub("?", text)


def trunc(text: str, width: int) -> str:
    """Truncate text cleanly to fit width."""
    s = sanitize_display(str(text if text is not None else "-"))
    if width <= 0:
        return ""
    if len(s) <= width:
        return s.ljust(width)
    if width <= 3:
        return s[:width]
    return (s[: width - 2] + "..").ljust(width)


def format_curl_command(item: Dict[str, Any]) -> str:
    """Generate a shell-safe cURL command (every dynamic value is quoted with shlex.quote)."""
    method = str(item.get("method", "POST")).upper()
    if not re.fullmatch(r"[A-Z]{3,7}", method):
        method = "POST"
    url = str(item.get("url", "https://api-satusehat-stg.dto.kemkes.go.id/fhir-r4/v1"))
    payload = item.get("request_payload", {})
    body_str = (
        json.dumps(payload, indent=2, ensure_ascii=False)
        if isinstance(payload, (dict, list))
        else str(payload)
    )
    lines = [
        f"curl -X {method} {shlex.quote(url)} \\",
        "  -H 'Authorization: Bearer <ACCESS_TOKEN>' \\",
        "  -H 'Content-Type: application/fhir+json' \\",
        f"  -d {shlex.quote(body_str)}",
    ]
    if item.get("pii_masked"):
        lines.insert(0, "# NOTE: payload below has masked personal data; replace masked values before replaying.")
    return "\n".join(lines)


def private_state_dir() -> str:
    """
    Per-user private directory (0700) for the clipboard fallback file / PID file.
    Prefers $XDG_RUNTIME_DIR, then ~/.cache, then a fresh mkdtemp. Refuses symlinks and foreign owners.
    """
    candidates = []
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        candidates.append(os.path.join(xdg, "satusehat-monitor"))
    candidates.append(os.path.join(os.path.expanduser("~"), ".cache", "satusehat-monitor"))
    for path in candidates:
        try:
            os.makedirs(path, mode=0o700, exist_ok=True)
            st = os.lstat(path)
            if stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid():
                os.chmod(path, 0o700)
                return path
        except OSError:
            continue
    return tempfile.mkdtemp(prefix="satusehat-monitor-")  # mode 0700 by construction


def write_private_file(path: str, text: str) -> None:
    """Write text with mode 0600, refusing to follow symlinks."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


def _write_osc52(text: str) -> bool:
    """Emit OSC 52 only on non-VTE SSH sessions and within safe terminal buffer size."""
    is_ssh = bool(os.environ.get("SSH_TTY") or os.environ.get("SSH_CONNECTION"))
    if not is_ssh or os.environ.get("VTE_VERSION"):
        return False
    raw = text.encode("utf-8")
    if len(raw) > 74000:
        return False
    try:
        encoded = base64.b64encode(raw).decode("ascii")
        if os.environ.get("TMUX"):
            seq = f"\033Ptmux;\033\033]52;c;{encoded}\a\033\\"
        else:
            seq = f"\033]52;c;{encoded}\a"
        with open("/dev/tty", "w", encoding="ascii") as tty:
            tty.write(seq)
            tty.flush()
        return True
    except Exception:
        return False


_CLIP_PROCS: List[subprocess.Popen] = []


def _copy_via_gtk3(fallback_file: str) -> bool:
    """Spawn a persistent X11/Wayland GTK3 clipboard holder (xclip-style) when CLI tools are absent."""
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    if not os.path.isfile(fallback_file):
        return False

    pid_file = os.path.join(os.path.dirname(fallback_file), "clip-holder.pid")

    # Reap/stop any previous holder processes so only the latest selection stays alive
    while _CLIP_PROCS:
        old_proc = _CLIP_PROCS.pop()
        try:
            if old_proc.poll() is None:
                old_proc.terminate()
                old_proc.wait(timeout=0.3)
        except (OSError, subprocess.SubprocessError):
            pass  # best-effort cleanup of a helper process

    if os.path.isfile(pid_file):
        try:
            with open(pid_file, "r", encoding="utf-8") as pf:
                old_pid = int(pf.read().strip())
            if old_pid > 1:
                os.kill(old_pid, signal.SIGTERM)
        except (OSError, ValueError):
            pass  # stale/missing pid file is fine

    script = (
        "import signal, sys, time, gi\n"
        "gi.require_version('Gtk', '3.0')\n"
        "from gi.repository import Gtk, Gdk\n"
        "Gtk.init([])\n"
        "with open(sys.argv[1], 'r', encoding='utf-8') as f:\n"
        "    text = f.read()\n"
        "cb = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)\n"
        "cb.set_text(text, -1)\n"
        "cb.store()\n"
        "end_init = time.time() + 0.08\n"
        "while time.time() < end_init:\n"
        "    while Gtk.events_pending():\n"
        "        Gtk.main_iteration_do(False)\n"
        "    time.sleep(0.01)\n"
        "cb.connect('owner-change', lambda *_: Gtk.main_quit())\n"
        "signal.signal(signal.SIGTERM, lambda *_: Gtk.main_quit())\n"
        "Gtk.main()\n"
    )
    try:
        # Fixed script + one path argument, no shell: nothing user-controlled is interpreted as code.
        proc = subprocess.Popen(  # nosec B603
            [sys.executable, "-c", script, fallback_file],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.12)
        rc = proc.poll()
        if rc is None or rc == 0:
            if rc is None:
                _CLIP_PROCS.append(proc)
            try:
                write_private_file(pid_file, str(proc.pid))
            except OSError:
                pass
            return True
        return False
    except Exception:
        return False


def format_json_text(data: Any) -> str:
    """Format dict/list as pretty JSON, or string as-is."""
    if isinstance(data, (dict, list)):
        return json.dumps(data, indent=2, ensure_ascii=False)
    return str(data if data is not None else "")


def copy_to_clipboard(text: str, fallback_file: str) -> str:
    """Copy text to system clipboard (CLI tools / GTK3 / SSH OSC52) and always save to fallback_file."""
    try:
        write_private_file(fallback_file, text)
    except OSError:
        pass

    for cmd in (
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
    ):
        try:
            # cmd comes from the fixed whitelist above; clipboard text goes via stdin, never argv.
            proc = subprocess.Popen(  # nosec B603
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            proc.communicate(input=text.encode("utf-8"), timeout=1.5)
            if proc.returncode == 0:
                return "Copied to clipboard"
        except (OSError, subprocess.SubprocessError):
            continue  # tool missing/failed: try the next clipboard backend

    if _copy_via_gtk3(fallback_file):
        return "Copied to clipboard"

    if _write_osc52(text):
        return f"Copied via OSC52 (also saved to {fallback_file})"

    return f"Saved to {fallback_file}"


class SatuSehatTUI:
    """Interactive curses TUI for SATUSEHAT FHIR transaction monitoring."""

    MODE_SPLIT = 1
    MODE_TABLE = 2
    MODE_INSPECT = 3
    MODE_SUMMARY = 4

    FOCUS_TABLE = 0
    FOCUS_REQ = 1
    FOCUS_RES = 2

    INSPECT_TAB_SPLIT = 0
    INSPECT_TAB_REQ = 1
    INSPECT_TAB_RES = 2
    INSPECT_TAB_CURL = 3

    def __init__(
        self,
        collector: TransactionCollector,
        base_dir: str,
        initial_status_filter: str = "ALL",
    ) -> None:
        self.collector = collector
        self.base_dir = base_dir
        self.copy_path = os.path.join(private_state_dir(), "last-copy.txt")
        atexit.register(self._cleanup_copy_files)

        self.mode: int = self.MODE_SPLIT
        self.focus_pane: int = self.FOCUS_TABLE
        self.inspect_tab: int = self.INSPECT_TAB_SPLIT

        self.selected_idx: int = 0
        self.selected_id: Optional[str] = None
        self.table_scroll: int = 0
        self.req_scroll: int = 0
        self.res_scroll: int = 0
        self.req_hscroll: int = 0
        self.res_hscroll: int = 0

        self.filter_resource: str = "ALL"
        self.filter_status: str = initial_status_filter
        self.search_query: str = ""
        self.is_searching: bool = False
        self.confirm_delete: bool = False

        self.status_notice: str = ""
        self.status_notice_until: float = 0.0

    def reset_json_scroll(self) -> None:
        self.req_scroll = 0
        self.res_scroll = 0
        self.req_hscroll = 0
        self.res_hscroll = 0

    def set_notice(self, msg: str, duration: float = 3.0) -> None:
        self.status_notice = msg
        self.status_notice_until = time.time() + duration

    def get_filtered_items(self) -> Tuple[List[Dict[str, Any]], int, int, int]:
        """Return (filtered_list, total_count, success_count, fail_count)."""
        all_items = self.collector.get_snapshot()
        total = len(all_items)
        sukses = sum(1 for x in all_items if x.get("status") == "Sukses")
        gagal = total - sukses

        filtered: List[Dict[str, Any]] = []
        q = self.search_query.strip().lower()

        for item in all_items:
            if self.filter_resource != "ALL" and item.get("resource_name") != self.filter_resource:
                continue
            if self.filter_status != "ALL" and item.get("status") != self.filter_status:
                continue
            if q:
                haystack = " ".join(
                    [
                        str(item.get("waktu_kirim", "")),
                        str(item.get("resource_name", "")),
                        str(item.get("method", "")),
                        str(item.get("status", "")),
                        str(item.get("rule_number", "")),
                        str(item.get("resource_id", "")),
                        str(item.get("encounter_id", "")),
                        str(item.get("patient_id", "")),
                        str(item.get("patient_name", "")),
                        str(item.get("id_registrasi", "")),
                        str(item.get("error_summary", "")),
                    ]
                ).lower()
                if q not in haystack:
                    continue
            filtered.append(item)

        return filtered, total, sukses, gagal

    def sync_selection(self, items: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Keep cursor locked to `selected_id` when user scrolled down,
        or auto-follow row 0 when cursor is at the top.
        """
        if not items:
            self.selected_idx = 0
            self.selected_id = None
            return None

        if self.selected_idx > 0 and self.selected_id:
            for idx, item in enumerate(items):
                if item.get("id") == self.selected_id:
                    self.selected_idx = idx
                    break

        if self.selected_idx >= len(items):
            self.selected_idx = len(items) - 1
        if self.selected_idx < 0:
            self.selected_idx = 0

        current = items[self.selected_idx]
        self.selected_id = str(current.get("id"))
        return current

    def init_colors(self) -> None:
        curses.start_color()
        curses.use_default_colors()

        curses.init_pair(CP_DEFAULT, curses.COLOR_WHITE, -1)
        curses.init_pair(CP_HEADER, curses.COLOR_CYAN, -1)
        curses.init_pair(CP_BORDER, curses.COLOR_WHITE, -1)
        curses.init_pair(CP_SUCCESS, curses.COLOR_GREEN, -1)
        curses.init_pair(CP_FAIL, curses.COLOR_RED, -1)
        curses.init_pair(CP_METHOD_POST, curses.COLOR_YELLOW, -1)
        curses.init_pair(CP_METHOD_PUT, curses.COLOR_CYAN, -1)
        curses.init_pair(CP_METHOD_GET, curses.COLOR_GREEN, -1)
        curses.init_pair(CP_DIM, curses.COLOR_WHITE, -1)
        curses.init_pair(CP_SELECTED, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(CP_JSON_KEY, curses.COLOR_CYAN, -1)
        curses.init_pair(CP_JSON_STR, curses.COLOR_GREEN, -1)
        curses.init_pair(CP_JSON_NUM, curses.COLOR_YELLOW, -1)
        curses.init_pair(CP_ACCENT, curses.COLOR_YELLOW, -1)

    def _cleanup_copy_files(self) -> None:
        """Remove the clipboard fallback file on exit so copied patient data is not left on disk."""
        for name in ("last-copy.txt",):
            try:
                os.remove(os.path.join(os.path.dirname(self.copy_path), name))
            except OSError:
                pass

    def safe_addstr(self, stdscr: Any, y: int, x: int, text: str, attr: int = 0) -> None:
        max_y, max_x = stdscr.getmaxyx()
        if y < 0 or y >= max_y or x >= max_x:
            return
        if x < 0:
            text = text[-x:]
            x = 0
        avail = max_x - x
        if avail <= 0:
            return
        clipped = sanitize_display(text[:avail])
        try:
            stdscr.addstr(y, x, clipped, attr)
        except curses.error:
            pass

    def draw_box(
        self,
        stdscr: Any,
        y: int,
        x: int,
        h: int,
        w: int,
        title: str = "",
        right_title: str = "",
        focused: bool = False,
    ) -> None:
        """Draw a clean rounded Unicode box (╭─╮│╰─╯) with optional focus highlight."""
        if h < 2 or w < 4:
            return
        if focused:
            b_attr = curses.color_pair(CP_ACCENT) | curses.A_BOLD
            t_attr = curses.color_pair(CP_ACCENT) | curses.A_BOLD
        else:
            b_attr = curses.color_pair(CP_BORDER) | curses.A_DIM
            t_attr = curses.color_pair(CP_HEADER) | curses.A_BOLD

        top_line = "╭" + ("─" * (w - 2)) + "╮"
        bot_line = "╰" + ("─" * (w - 2)) + "╯"
        self.safe_addstr(stdscr, y, x, top_line, b_attr)
        for row in range(y + 1, y + h - 1):
            self.safe_addstr(stdscr, row, x, "│", b_attr)
            self.safe_addstr(stdscr, row, x + w - 1, "│", b_attr)
        self.safe_addstr(stdscr, y + h - 1, x, bot_line, b_attr)

        if title:
            label = f" {title} "
            self.safe_addstr(stdscr, y, x + 2, label, t_attr)
        if right_title:
            rlabel = f" {right_title} "
            rx = x + w - len(rlabel) - 2
            if rx > x + len(title) + 4:
                self.safe_addstr(
                    stdscr,
                    y,
                    rx,
                    rlabel,
                    curses.color_pair(CP_ACCENT) | curses.A_BOLD if focused else curses.color_pair(CP_DIM),
                )

    def compute_column_widths(self, inner_w: int) -> Dict[str, int]:
        """
        Compute responsive widths for the 9 table columns:
        WAKTU KIRIM | RESOURCE NAME | METHOD | STATUS | RESPONSE | RULE | RESOURCE ID | ENCOUNTER ID | PATIENT ID
        Ensures total width never exceeds inner_w so PATIENT ID is always visible in full.
        """
        c_prefix = 2  # "> " or "  "
        c_waktu = 17  # "16/10/26 13:31:45"
        c_method = 6  # "POST  "
        c_status = 6  # "Sukses"
        c_resp = 12   # "201 Created " / "400 Bad Req "
        c_rule = 6    # "20002 "
        c_pat = 12    # "P20396178759"
        gaps = 8 * 2  # 2 spaces between 9 columns

        fixed_sum = c_prefix + c_waktu + c_method + c_status + c_resp + c_rule + c_pat + gaps
        rem = max(24, inner_w - fixed_sum)

        c_res_name = max(12, min(18, int(rem * 0.36)))
        leftover = max(12, rem - c_res_name)
        c_res_id = max(6, leftover // 2)
        c_enc_id = max(6, leftover - c_res_id)

        return {
            "waktu": c_waktu,
            "resource": c_res_name,
            "method": c_method,
            "status": c_status,
            "response": c_resp,
            "rule": c_rule,
            "resource_id": c_res_id,
            "encounter_id": c_enc_id,
            "patient_id": c_pat,
        }

    def draw_top_bar(
        self,
        stdscr: Any,
        w: int,
        total: int,
        sukses: int,
        gagal: int,
    ) -> None:
        """Draw the clean 1-line header box without [LIVE]/env/org."""
        self.draw_box(stdscr, 0, 0, 3, w)

        title = "SATUSEHAT FHIR MONITOR"
        self.safe_addstr(stdscr, 1, 2, title, curses.color_pair(CP_HEADER) | curses.A_BOLD)

        mode_names = [
            (1, "Split"),
            (2, "Table"),
            (3, "Inspect"),
            (4, "Summary"),
        ]
        mx = 2 + len(title) + 3
        for m_num, m_label in mode_names:
            tag = f"[{m_num}]{m_label}"
            if self.mode == m_num:
                attr = curses.color_pair(CP_ACCENT) | curses.A_BOLD
            else:
                attr = curses.color_pair(CP_DIM) | curses.A_DIM
            self.safe_addstr(stdscr, 1, mx, tag, attr)
            mx += len(tag) + 2

        # Right-side stats & active filters
        search_disp = self.search_query if self.search_query else "-"
        stats_str = (
            f"total: {total} | sukses: {sukses} | gagal: {gagal} | "
            f"filter: {self.filter_resource}/{self.filter_status} | search: {search_disp}"
        )
        sx = max(mx + 1, w - len(stats_str) - 2)
        if sx < w - 3:
            self.safe_addstr(stdscr, 1, sx, stats_str[: w - sx - 2], curses.color_pair(CP_DEFAULT))

    def draw_table_section(
        self,
        stdscr: Any,
        y: int,
        h: int,
        w: int,
        items: List[Dict[str, Any]],
    ) -> None:
        """Draw the 9-column FHIR transaction table."""
        is_focused = self.mode == self.MODE_TABLE or self.focus_pane == self.FOCUS_TABLE
        scroll_state = "AUTO-FOLLOW" if self.selected_idx == 0 else "SCROLL-LOCKED"
        right_info = f"{self.selected_idx + 1}/{len(items)} ({scroll_state})" if items else "0/0"
        self.draw_box(
            stdscr,
            y,
            0,
            h,
            w,
            title="Log Transaksi FHIR",
            right_title=right_info,
            focused=is_focused and self.mode == self.MODE_SPLIT,
        )

        if h < 5:
            return

        inner_w = w - 4
        cols = self.compute_column_widths(inner_w)

        # Header row
        hdr = (
            "  "
            + trunc("WAKTU KIRIM", cols["waktu"]) + "  "
            + trunc("RESOURCE NAME", cols["resource"]) + "  "
            + trunc("METHOD", cols["method"]) + "  "
            + trunc("STATUS", cols["status"]) + "  "
            + trunc("RESPONSE", cols["response"]) + "  "
            + trunc("RULE", cols["rule"]) + "  "
            + trunc("RESOURCE ID", cols["resource_id"]) + "  "
            + trunc("ENCOUNTER ID", cols["encounter_id"]) + "  "
            + trunc("PATIENT ID", cols["patient_id"])
        )
        self.safe_addstr(stdscr, y + 1, 2, hdr[:inner_w], curses.color_pair(CP_HEADER) | curses.A_BOLD)
        self.safe_addstr(
            stdscr,
            y + 2,
            2,
            "─" * inner_w,
            curses.color_pair(CP_BORDER) | curses.A_DIM,
        )

        body_rows = max(1, h - 4)
        if self.selected_idx < self.table_scroll:
            self.table_scroll = self.selected_idx
        elif self.selected_idx >= self.table_scroll + body_rows:
            self.table_scroll = self.selected_idx - body_rows + 1

        if not items:
            has_any = bool(self.collector.get_snapshot())
            empty_msg = (
                "Tidak ada transaksi yang cocok dengan filter saat ini."
                if has_any
                else f"Menunggu transaksi di {self.collector.source_label}... Pastikan satusehat-proxy berjalan & .env mengarah ke proxy."
            )
            self.safe_addstr(
                stdscr,
                y + 3,
                4,
                empty_msg[: max(10, inner_w - 4)],
                curses.color_pair(CP_DIM) | curses.A_DIM,
            )
            return

        visible = items[self.table_scroll : self.table_scroll + body_rows]
        for idx, item in enumerate(visible):
            abs_idx = self.table_scroll + idx
            row_y = y + 3 + idx
            is_sel = abs_idx == self.selected_idx

            prefix = "> " if is_sel else "  "
            waktu = trunc(item.get("waktu_kirim", "-"), cols["waktu"])
            res_name = trunc(item.get("resource_name", "-"), cols["resource"])
            method = trunc(item.get("method", "-"), cols["method"])
            status = trunc(item.get("status", "-"), cols["status"])
            resp = trunc(item.get("response", "-"), cols["response"])
            rule = trunc(item.get("rule_number", "-"), cols["rule"])
            res_id = trunc(item.get("resource_id", "-"), cols["resource_id"])
            enc_id = trunc(item.get("encounter_id", "-"), cols["encounter_id"])
            pat_id = trunc(item.get("patient_id", "-"), cols["patient_id"])

            if is_sel:
                full_line = (
                    f"{prefix}{waktu}  {res_name}  {method}  {status}  "
                    f"{resp}  {rule}  {res_id}  {enc_id}  {pat_id}"
                )
                self.safe_addstr(
                    stdscr,
                    row_y,
                    2,
                    full_line.ljust(inner_w)[:inner_w],
                    curses.color_pair(CP_SELECTED) | curses.A_BOLD,
                )
            else:
                cx = 2
                self.safe_addstr(stdscr, row_y, cx, prefix, curses.color_pair(CP_DEFAULT))
                cx += 2
                self.safe_addstr(stdscr, row_y, cx, waktu + "  ", curses.color_pair(CP_DEFAULT))
                cx += cols["waktu"] + 2
                self.safe_addstr(
                    stdscr, row_y, cx, res_name + "  ", curses.color_pair(CP_DEFAULT) | curses.A_BOLD
                )
                cx += cols["resource"] + 2

                m_val = item.get("method", "").upper()
                m_pair = (
                    CP_METHOD_PUT
                    if m_val == "PUT"
                    else (CP_METHOD_POST if m_val == "POST" else CP_METHOD_GET)
                )
                self.safe_addstr(stdscr, row_y, cx, method + "  ", curses.color_pair(m_pair) | curses.A_BOLD)
                cx += cols["method"] + 2

                is_ok = item.get("status") == "Sukses"
                s_pair = CP_SUCCESS if is_ok else CP_FAIL
                self.safe_addstr(stdscr, row_y, cx, status + "  ", curses.color_pair(s_pair) | curses.A_BOLD)
                cx += cols["status"] + 2

                self.safe_addstr(
                    stdscr,
                    row_y,
                    cx,
                    resp + "  ",
                    curses.color_pair(CP_DEFAULT if is_ok else CP_FAIL),
                )
                cx += cols["response"] + 2

                r_attr = (
                    curses.color_pair(CP_FAIL) | curses.A_BOLD
                    if item.get("rule_number", "-") != "-"
                    else curses.color_pair(CP_DIM) | curses.A_DIM
                )
                self.safe_addstr(stdscr, row_y, cx, rule + "  ", r_attr)
                cx += cols["rule"] + 2

                self.safe_addstr(stdscr, row_y, cx, res_id + "  ", curses.color_pair(CP_DEFAULT))
                cx += cols["resource_id"] + 2

                self.safe_addstr(stdscr, row_y, cx, enc_id + "  ", curses.color_pair(CP_DEFAULT))
                cx += cols["encounter_id"] + 2

                self.safe_addstr(stdscr, row_y, cx, pat_id, curses.color_pair(CP_HEADER))

    def draw_json_lines(
        self,
        stdscr: Any,
        start_y: int,
        start_x: int,
        max_h: int,
        max_w: int,
        data: Any,
        scroll_offset: int = 0,
        hscroll_offset: int = 0,
        banner_line: str = "",
    ) -> int:
        """Render formatted JSON with clean syntax coloring inside a box. Returns total line count."""
        if max_h <= 0 or max_w <= 2:
            return 0

        row_offset = 0
        if banner_line:
            self.safe_addstr(
                stdscr,
                start_y,
                start_x,
                banner_line[:max_w],
                curses.color_pair(CP_FAIL) | curses.A_BOLD,
            )
            row_offset = 1
            if max_h <= 1:
                return 1

        if isinstance(data, (dict, list)):
            text = json.dumps(data, indent=2, ensure_ascii=False)
        else:
            text = str(data or "")

        lines = text.splitlines()
        total_lines = len(lines)
        visible = lines[scroll_offset : scroll_offset + (max_h - row_offset)]

        for idx, raw_line in enumerate(visible):
            ry = start_y + row_offset + idx
            line = raw_line[hscroll_offset:] if hscroll_offset < len(raw_line) else ""
            clipped = line[:max_w]

            if '":' in clipped:
                colon_pos = clipped.find('":') + 2
                key_part = clipped[:colon_pos]
                val_part = clipped[colon_pos:]
                self.safe_addstr(stdscr, ry, start_x, key_part, curses.color_pair(CP_JSON_KEY))
                v_strip = val_part.strip()
                if v_strip.startswith('"'):
                    v_attr = curses.color_pair(CP_JSON_STR)
                elif v_strip[:1].isdigit() or v_strip.startswith("true") or v_strip.startswith("false"):
                    v_attr = curses.color_pair(CP_JSON_NUM)
                else:
                    v_attr = curses.color_pair(CP_DEFAULT)
                self.safe_addstr(stdscr, ry, start_x + len(key_part), val_part, v_attr)
            else:
                self.safe_addstr(stdscr, ry, start_x, clipped, curses.color_pair(CP_DEFAULT))

        return total_lines

    def draw_split_inspector(
        self,
        stdscr: Any,
        y: int,
        h: int,
        w: int,
        current: Optional[Dict[str, Any]],
    ) -> None:
        """Draw bottom side-by-side Request Payload and Response Body boxes with scroll indicators."""
        if h < 4:
            return
        left_w = w // 2
        right_w = w - left_w

        req_focused = self.focus_pane == self.FOCUS_REQ
        res_focused = self.focus_pane == self.FOCUS_RES

        if not current:
            self.draw_box(stdscr, y, 0, h, left_w, title="Request Payload", focused=req_focused)
            self.draw_box(stdscr, y, left_w, h, right_w, title="Response Body", focused=res_focused)
            return

        method = current.get("method", "POST")
        res_name = current.get("resource_name", "FHIR")
        resp_label = current.get("response", "")
        pat_id = current.get("patient_id", "-")
        enc_id = current.get("encounter_id", "-")

        req_data = current.get("request_payload")
        res_data = current.get("response_payload")
        req_total = len(
            (json.dumps(req_data, indent=2) if isinstance(req_data, (dict, list)) else str(req_data or "")).splitlines()
        )
        res_total = len(
            (json.dumps(res_data, indent=2) if isinstance(res_data, (dict, list)) else str(res_data or "")).splitlines()
        )

        self.req_scroll = max(0, min(self.req_scroll, max(0, req_total - (h - 3))))
        self.res_scroll = max(0, min(self.res_scroll, max(0, res_total - (h - 3))))

        req_title = f"Request Payload ({method} /{res_name})"
        lat_ms = int(current.get("latency_ms") or 0)
        lat_suffix = f" · {lat_ms}ms" if lat_ms > 0 else ""
        res_title = f"Response Body ({resp_label}{lat_suffix})"

        req_right = (
            f"[SCROLL ↑/↓ line {self.req_scroll + 1}/{req_total}]"
            if req_focused
            else f"line {self.req_scroll + 1}/{req_total} (Tab: focus)"
        )
        res_right = (
            f"[SCROLL ↑/↓ line {self.res_scroll + 1}/{res_total}]"
            if res_focused
            else f"Patient: {pat_id} | Enc: {enc_id[:13]}"
        )

        self.draw_box(stdscr, y, 0, h, left_w, title=req_title, right_title=req_right, focused=req_focused)
        self.draw_box(stdscr, y, left_w, h, right_w, title=res_title, right_title=res_right, focused=res_focused)

        err_banner = ""
        if current.get("status") == "Gagal":
            rule = current.get("rule_number", "-")
            err_sum = current.get("error_summary", "")
            if rule != "-" or err_sum:
                err_banner = f"Rule {rule}: {err_sum}"

        self.draw_json_lines(
            stdscr,
            y + 1,
            2,
            h - 2,
            left_w - 4,
            req_data,
            scroll_offset=self.req_scroll,
            hscroll_offset=self.req_hscroll,
        )
        self.draw_json_lines(
            stdscr,
            y + 1,
            left_w + 2,
            h - 2,
            right_w - 4,
            res_data,
            scroll_offset=self.res_scroll,
            hscroll_offset=self.res_hscroll,
            banner_line=err_banner,
        )

    def draw_full_inspector_mode(
        self,
        stdscr: Any,
        y: int,
        h: int,
        w: int,
        current: Optional[Dict[str, Any]],
    ) -> None:
        """Draw Mode 3: Full Transaction Detail & JSON/cURL Inspector."""
        if not current or h < 8:
            self.draw_box(stdscr, y, 0, h, w, title="Transaction Detail")
            return

        meta_h = 8
        self.draw_box(
            stdscr,
            y,
            0,
            meta_h,
            w,
            title="Transaction Detail (Full Metadata)",
            right_title="Esc/Enter: Back to Split",
        )

        col2_x = max(48, w // 2)
        c_label = curses.color_pair(CP_DIM) | curses.A_DIM
        c_val = curses.color_pair(CP_DEFAULT) | curses.A_BOLD
        is_ok = current.get("status") == "Sukses"

        # Left metadata column
        self.safe_addstr(stdscr, y + 1, 2, "Waktu Kirim  : ", c_label)
        self.safe_addstr(stdscr, y + 1, 17, str(current.get("waktu_kirim", "-")), c_val)

        self.safe_addstr(stdscr, y + 2, 2, "Resource     : ", c_label)
        self.safe_addstr(
            stdscr,
            y + 2,
            17,
            f"{current.get('method', '-')} {current.get('resource_name', '-')}",
            curses.color_pair(CP_HEADER) | curses.A_BOLD,
        )

        self.safe_addstr(stdscr, y + 3, 2, "Resource ID  : ", c_label)
        self.safe_addstr(stdscr, y + 3, 17, str(current.get("resource_id", "-")), c_val)

        self.safe_addstr(stdscr, y + 4, 2, "Encounter ID : ", c_label)
        self.safe_addstr(stdscr, y + 4, 17, str(current.get("encounter_id", "-")), c_val)

        self.safe_addstr(stdscr, y + 5, 2, "Endpoint URL : ", c_label)
        self.safe_addstr(
            stdscr,
            y + 5,
            17,
            str(current.get("url", "-"))[: w - 20],
            curses.color_pair(CP_DEFAULT),
        )

        # Right metadata column
        self.safe_addstr(stdscr, y + 1, col2_x, "Status / Resp : ", c_label)
        self.safe_addstr(
            stdscr,
            y + 1,
            col2_x + 16,
            f"{current.get('status', '-')} ({current.get('response', '-')})",
            curses.color_pair(CP_SUCCESS if is_ok else CP_FAIL) | curses.A_BOLD,
        )

        self.safe_addstr(stdscr, y + 2, col2_x, "Rule Number   : ", c_label)
        self.safe_addstr(
            stdscr,
            y + 2,
            col2_x + 16,
            str(current.get("rule_number", "-")),
            curses.color_pair(CP_FAIL if current.get("rule_number", "-") != "-" else CP_DEFAULT),
        )

        pat_disp = str(current.get("patient_id", "-"))
        if current.get("patient_name", "-") != "-":
            pat_disp += f" ({current.get('patient_name')})"
        self.safe_addstr(stdscr, y + 3, col2_x, "Patient ID    : ", c_label)
        self.safe_addstr(stdscr, y + 3, col2_x + 16, pat_disp, curses.color_pair(CP_HEADER) | curses.A_BOLD)

        self.safe_addstr(stdscr, y + 4, col2_x, "No Registrasi : ", c_label)
        self.safe_addstr(stdscr, y + 4, col2_x + 16, str(current.get("id_registrasi", "-")), c_val)

        lat_ms = int(current.get("latency_ms") or 0)
        lat_disp = f"{lat_ms} ms" if lat_ms > 0 else "-"
        self.safe_addstr(stdscr, y + 5, col2_x, "Latency       : ", c_label)
        self.safe_addstr(stdscr, y + 5, col2_x + 16, lat_disp, c_val)

        err_sum = current.get("error_summary", "")
        if err_sum:
            self.safe_addstr(stdscr, y + 6, 2, "Error Detail : ", curses.color_pair(CP_FAIL) | curses.A_BOLD)
            self.safe_addstr(
                stdscr,
                y + 6,
                17,
                err_sum[: w - 20],
                curses.color_pair(CP_FAIL),
            )

        pane_y = y + meta_h
        pane_h = h - meta_h
        if pane_h < 4:
            return

        tabs = [
            (self.INSPECT_TAB_SPLIT, "Split Req/Res"),
            (self.INSPECT_TAB_REQ, "Request Full"),
            (self.INSPECT_TAB_RES, "Response Full"),
            (self.INSPECT_TAB_CURL, "cURL Command"),
        ]
        tab_str = "  ".join(
            f"[{'*' if self.inspect_tab == tid else ' '}{tname}]" for tid, tname in tabs
        ) + "  (h/l: switch view, ↑/↓ or j/k: scroll)"

        if self.inspect_tab == self.INSPECT_TAB_SPLIT:
            self.draw_split_inspector(stdscr, pane_y, pane_h, w, current)
        elif self.inspect_tab == self.INSPECT_TAB_REQ:
            self.draw_box(stdscr, pane_y, 0, pane_h, w, title="Request Payload", right_title=tab_str, focused=True)
            self.draw_json_lines(
                stdscr,
                pane_y + 1,
                2,
                pane_h - 2,
                w - 4,
                current.get("request_payload"),
                scroll_offset=self.req_scroll,
            )
        elif self.inspect_tab == self.INSPECT_TAB_RES:
            self.draw_box(stdscr, pane_y, 0, pane_h, w, title="Response Body", right_title=tab_str, focused=True)
            self.draw_json_lines(
                stdscr,
                pane_y + 1,
                2,
                pane_h - 2,
                w - 4,
                current.get("response_payload"),
                scroll_offset=self.res_scroll,
            )
        elif self.inspect_tab == self.INSPECT_TAB_CURL:
            self.draw_box(stdscr, pane_y, 0, pane_h, w, title="cURL Command", right_title=tab_str, focused=True)
            curl_txt = format_curl_command(current)
            self.draw_json_lines(
                stdscr,
                pane_y + 1,
                2,
                pane_h - 2,
                w - 4,
                curl_txt,
                scroll_offset=self.req_scroll,
            )

    def draw_summary_mode(self, stdscr: Any, y: int, h: int, w: int) -> None:
        """Draw Mode 4: Ringkasan Transaksi FHIR (aggregated per Resource Name)."""
        self.draw_box(
            stdscr,
            y,
            0,
            h,
            w,
            title="Ringkasan Transaksi FHIR (Per Resource)",
            right_title="Press 1 for Split View",
        )
        if h < 5:
            return

        all_items = self.collector.get_snapshot()
        stats: Dict[str, Dict[str, Any]] = {}
        for item in all_items:
            rname = str(item.get("resource_name", "FHIR"))
            entry = stats.setdefault(
                rname,
                {"total": 0, "sukses": 0, "gagal": 0, "last_time": "-"},
            )
            entry["total"] += 1
            if item.get("status") == "Sukses":
                entry["sukses"] += 1
            else:
                entry["gagal"] += 1
            if entry["last_time"] == "-":
                entry["last_time"] = item.get("waktu_kirim", "-")

        inner_w = w - 4
        hdr = (
            f"  {'RESOURCE NAME':<24}  {'TOTAL':>8}  {'SUKSES':>8}  "
            f"{'GAGAL':>8}  {'SUCCESS RATE':>14}  {'LAST ACTIVITY':<20}"
        )
        self.safe_addstr(stdscr, y + 1, 2, hdr[:inner_w], curses.color_pair(CP_HEADER) | curses.A_BOLD)
        self.safe_addstr(
            stdscr,
            y + 2,
            2,
            "─" * inner_w,
            curses.color_pair(CP_BORDER) | curses.A_DIM,
        )

        sorted_res = sorted(stats.items(), key=lambda kv: kv[1]["total"], reverse=True)
        for idx, (rname, st) in enumerate(sorted_res[: max(1, h - 4)]):
            ry = y + 3 + idx
            tot = st["total"]
            ok = st["sukses"]
            fail = st["gagal"]
            rate = (ok / tot * 100.0) if tot > 0 else 0.0
            line = (
                f"  {rname:<24}  {tot:>8}  {ok:>8}  "
                f"{fail:>8}  {rate:>13.1f}%  {st['last_time']:<20}"
            )
            attr = curses.color_pair(CP_SUCCESS if fail == 0 else CP_DEFAULT)
            self.safe_addstr(stdscr, ry, 2, line[:inner_w], attr)

    def draw_footer(self, stdscr: Any, y: int, w: int) -> None:
        """Draw bottom keybind bar, delete confirmation, or active search input bar."""
        if self.confirm_delete:
            prompt = "  Hapus file log di disk?  [y] Hari ini   [a] Semua file log   [n/Esc] Batal"
            self.safe_addstr(stdscr, y, 0, prompt.ljust(w)[:w], curses.color_pair(CP_FAIL) | curses.A_BOLD)
            return

        if self.is_searching:
            prompt = f"  Search (Resource/Encounter/Patient/Rule): {self.search_query}_   [Enter/Esc: Done]"
            self.safe_addstr(stdscr, y, 0, prompt.ljust(w)[:w], curses.color_pair(CP_ACCENT) | curses.A_BOLD)
            return

        if self.status_notice and time.time() < self.status_notice_until:
            notice = f"  * {self.status_notice}"
            self.safe_addstr(stdscr, y, 0, notice.ljust(w)[:w], curses.color_pair(CP_SUCCESS) | curses.A_BOLD)
            return

        focus_names = {
            self.FOCUS_TABLE: "TABLE",
            self.FOCUS_REQ: "REQUEST JSON",
            self.FOCUS_RES: "RESPONSE JSON",
        }
        f_label = focus_names.get(self.focus_pane, "TABLE")
        help_line = (
            f"  [Tab] Focus: {f_label}   j/k: move   J/K: json   enter: inspect   "
            "1-4: mode   /: search   f: res   e: err   r: reload   c: copy   R/P: res/req   D: del log   q: quit"
        )
        self.safe_addstr(
            stdscr,
            y,
            0,
            help_line.ljust(w)[:w],
            curses.color_pair(CP_DIM) | curses.A_DIM,
        )

    def cycle_resource_filter(self) -> None:
        all_items = self.collector.get_snapshot()
        resources = sorted({str(x.get("resource_name", "FHIR")) for x in all_items if x.get("resource_name")})
        options = ["ALL"] + resources
        try:
            idx = options.index(self.filter_resource)
            self.filter_resource = options[(idx + 1) % len(options)]
        except ValueError:
            self.filter_resource = "ALL"
        self.selected_idx = 0
        self.table_scroll = 0
        self.set_notice(f"Filter Resource: {self.filter_resource}", 1.5)

    def cycle_status_filter(self) -> None:
        options = ["ALL", "Sukses", "Gagal"]
        try:
            idx = options.index(self.filter_status)
            self.filter_status = options[(idx + 1) % len(options)]
        except ValueError:
            self.filter_status = "ALL"
        self.selected_idx = 0
        self.table_scroll = 0
        self.set_notice(f"Filter Status: {self.filter_status}", 1.5)

    def scroll_active_json(self, delta: int) -> None:
        if self.focus_pane == self.FOCUS_REQ or (
            self.mode == self.MODE_INSPECT and self.inspect_tab in (self.INSPECT_TAB_REQ, self.INSPECT_TAB_CURL)
        ):
            self.req_scroll = max(0, self.req_scroll + delta)
        elif self.focus_pane == self.FOCUS_RES or (
            self.mode == self.MODE_INSPECT and self.inspect_tab == self.INSPECT_TAB_RES
        ):
            self.res_scroll = max(0, self.res_scroll + delta)
        else:
            # Scroll both panes simultaneously when focus is on Table or Split Inspect
            self.req_scroll = max(0, self.req_scroll + delta)
            self.res_scroll = max(0, self.res_scroll + delta)

    def run(self, stdscr: Any) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(100)
        try:
            curses.mousemask(curses.ALL_MOUSE_EVENTS)
        except curses.error:
            pass  # terminal without mouse support
        self.init_colors()

        while True:
            stdscr.erase()
            max_y, max_x = stdscr.getmaxyx()

            if max_y < 12 or max_x < 60:
                self.safe_addstr(
                    stdscr,
                    0,
                    0,
                    f"Terminal terlalu kecil ({max_x}x{max_y}). Perbesar minimal 80x16.",
                    curses.color_pair(CP_FAIL) | curses.A_BOLD,
                )
                stdscr.refresh()
                ch = stdscr.getch()
                if ch in (ord("q"), ord("Q")):
                    break
                continue

            filtered, total, sukses, gagal = self.get_filtered_items()
            current = self.sync_selection(filtered)

            # 1. Top Bar (height 3)
            self.draw_top_bar(stdscr, max_x, total, sukses, gagal)

            # 2. Main Body Area (y=3 to max_y-2)
            body_y = 3
            body_h = max_y - 4

            if self.mode == self.MODE_SPLIT:
                table_h = max(7, int(body_h * 0.52))
                inspect_h = body_h - table_h
                self.draw_table_section(stdscr, body_y, table_h, max_x, filtered)
                self.draw_split_inspector(stdscr, body_y + table_h, inspect_h, max_x, current)
            elif self.mode == self.MODE_TABLE:
                self.draw_table_section(stdscr, body_y, body_h, max_x, filtered)
            elif self.mode == self.MODE_INSPECT:
                self.draw_full_inspector_mode(stdscr, body_y, body_h, max_x, current)
            elif self.mode == self.MODE_SUMMARY:
                self.draw_summary_mode(stdscr, body_y, body_h, max_x)

            # 3. Bottom Keybind / Search Bar
            self.draw_footer(stdscr, max_y - 1, max_x)
            stdscr.refresh()

            ch = stdscr.getch()
            if ch == -1:
                continue

            if self.confirm_delete:
                if ch in (ord("y"), ord("Y")):
                    ok, msg = self.collector.delete_logs(delete_all=False)
                    self.selected_idx = 0
                    self.selected_id = None
                    self.table_scroll = 0
                    self.reset_json_scroll()
                    self.set_notice(msg, 2.5)
                elif ch in (ord("a"), ord("A")):
                    ok, msg = self.collector.delete_logs(delete_all=True)
                    self.selected_idx = 0
                    self.selected_id = None
                    self.table_scroll = 0
                    self.reset_json_scroll()
                    self.set_notice(msg, 2.5)
                else:
                    self.set_notice("Hapus log dibatalkan", 1.5)
                self.confirm_delete = False
                continue

            if self.is_searching:
                if ch in (10, 13, 27):  # Enter or Esc
                    self.is_searching = False
                elif ch in (curses.KEY_BACKSPACE, 127, 8):
                    self.search_query = self.search_query[:-1]
                    self.selected_idx = 0
                elif 32 <= ch <= 126:
                    self.search_query += chr(ch)
                    self.selected_idx = 0
                continue

            # Mouse wheel support
            if ch == curses.KEY_MOUSE:
                try:
                    _, mx, my, _, bstate = curses.getmouse()
                    table_bottom = 3 + max(7, int((max_y - 4) * 0.52))
                    wheel_down = bool(bstate & getattr(curses, "BUTTON5_PRESSED", 0x200000))
                    wheel_up = bool(bstate & getattr(curses, "BUTTON4_PRESSED", 0x80000))
                    if wheel_down or wheel_up:
                        step = 2 if wheel_down else -2
                        if self.mode == self.MODE_SPLIT and my >= table_bottom:
                            if mx < max_x // 2:
                                self.req_scroll = max(0, self.req_scroll + step)
                            else:
                                self.res_scroll = max(0, self.res_scroll + step)
                        elif self.mode == self.MODE_INSPECT:
                            self.scroll_active_json(step)
                        else:
                            if filtered:
                                self.selected_idx = max(0, min(len(filtered) - 1, self.selected_idx + (1 if wheel_down else -1)))
                                self.selected_id = str(filtered[self.selected_idx].get("id"))
                                self.reset_json_scroll()
                except (curses.error, ValueError):
                    pass  # malformed mouse event
                continue

            if ch in (ord("q"), ord("Q")):
                break
            elif ch == 9:  # Tab key: cycle focus between Table -> Request Payload -> Response Body
                if self.mode == self.MODE_SPLIT:
                    self.focus_pane = (self.focus_pane + 1) % 3
                    pane_label = ["Log Transaksi FHIR (Table)", "Request Payload", "Response Body"][self.focus_pane]
                    self.set_notice(f"Focus: {pane_label} (gunakan ↑/↓ atau j/k untuk scroll)", 2.0)
                elif self.mode == self.MODE_INSPECT:
                    self.focus_pane = self.FOCUS_RES if self.focus_pane == self.FOCUS_REQ else self.FOCUS_REQ
            elif ch == ord("/"):
                self.is_searching = True
            elif ch == 27:  # Esc
                if self.focus_pane != self.FOCUS_TABLE:
                    self.focus_pane = self.FOCUS_TABLE
                    self.set_notice("Focus kembali ke Tabel Transaksi", 1.5)
                elif self.mode == self.MODE_INSPECT:
                    self.mode = self.MODE_SPLIT
                elif self.search_query:
                    self.search_query = ""
                    self.selected_idx = 0
            elif ch == ord("1"):
                self.mode = self.MODE_SPLIT
            elif ch in (ord("2"), ord("t")):
                self.mode = self.MODE_TABLE if self.mode != self.MODE_TABLE else self.MODE_SPLIT
                self.focus_pane = self.FOCUS_TABLE
            elif ch == ord("3"):
                self.mode = self.MODE_INSPECT
                if self.focus_pane == self.FOCUS_TABLE:
                    self.focus_pane = self.FOCUS_REQ
            elif ch in (ord("4"), ord("m")):
                self.mode = self.MODE_SUMMARY if self.mode != self.MODE_SUMMARY else self.MODE_SPLIT
            elif ch in (10, 13):  # Enter
                if self.mode in (self.MODE_SPLIT, self.MODE_TABLE):
                    self.mode = self.MODE_INSPECT
                    self.focus_pane = self.FOCUS_REQ
                else:
                    self.mode = self.MODE_SPLIT
                    self.focus_pane = self.FOCUS_TABLE
            elif ch in (curses.KEY_DOWN, ord("j")):
                if self.mode == self.MODE_INSPECT or self.focus_pane in (self.FOCUS_REQ, self.FOCUS_RES):
                    self.scroll_active_json(1)
                else:
                    if filtered and self.selected_idx < len(filtered) - 1:
                        self.selected_idx += 1
                        self.selected_id = str(filtered[self.selected_idx].get("id"))
                        self.reset_json_scroll()
            elif ch in (curses.KEY_UP, ord("k")):
                if self.mode == self.MODE_INSPECT or self.focus_pane in (self.FOCUS_REQ, self.FOCUS_RES):
                    self.scroll_active_json(-1)
                else:
                    if filtered and self.selected_idx > 0:
                        self.selected_idx -= 1
                        self.selected_id = str(filtered[self.selected_idx].get("id"))
                        self.reset_json_scroll()
            elif ch == ord("g"):
                if self.focus_pane in (self.FOCUS_REQ, self.FOCUS_RES) or self.mode == self.MODE_INSPECT:
                    self.reset_json_scroll()
                else:
                    self.selected_idx = 0
                    self.table_scroll = 0
                    self.reset_json_scroll()
                    if filtered:
                        self.selected_id = str(filtered[0].get("id"))
            elif ch == ord("G"):
                if self.focus_pane == self.FOCUS_REQ:
                    self.req_scroll = 9999
                elif self.focus_pane == self.FOCUS_RES:
                    self.res_scroll = 9999
                elif filtered:
                    self.selected_idx = len(filtered) - 1
                    self.selected_id = str(filtered[-1].get("id"))
                    self.reset_json_scroll()
            elif ch in (ord("J"), curses.KEY_NPAGE, ord("]")):
                self.scroll_active_json(4)
            elif ch in (ord("K"), curses.KEY_PPAGE, ord("[")):
                self.scroll_active_json(-4)
            elif ch in (ord("l"), curses.KEY_RIGHT):
                if self.mode == self.MODE_INSPECT:
                    self.inspect_tab = (self.inspect_tab + 1) % 4
                    self.reset_json_scroll()
                elif self.focus_pane == self.FOCUS_REQ:
                    self.req_hscroll += 6
                elif self.focus_pane == self.FOCUS_RES:
                    self.res_hscroll += 6
            elif ch in (ord("h"), curses.KEY_LEFT):
                if self.mode == self.MODE_INSPECT:
                    self.inspect_tab = (self.inspect_tab - 1) % 4
                    self.reset_json_scroll()
                elif self.focus_pane == self.FOCUS_REQ:
                    self.req_hscroll = max(0, self.req_hscroll - 6)
                elif self.focus_pane == self.FOCUS_RES:
                    self.res_hscroll = max(0, self.res_hscroll - 6)
            elif ch == ord("f"):
                self.cycle_resource_filter()
            elif ch == ord("s"):
                self.cycle_status_filter()
            elif ch == ord("e"):
                self.filter_status = "Gagal" if self.filter_status != "Gagal" else "ALL"
                self.selected_idx = 0
                self.table_scroll = 0
                self.set_notice(
                    "Filter: ERROR / GAGAL ONLY" if self.filter_status == "Gagal" else "Filter: ALL",
                    1.8,
                )
            elif ch == ord("r"):
                count = self.collector.reload_now()
                self.set_notice(f"Reloaded {count} transactions", 1.8)
            elif ch == ord("C"):
                self.collector.clear_view()
                self.selected_idx = 0
                self.selected_id = None
                self.table_scroll = 0
                self.reset_json_scroll()
                self.set_notice("Layar dibersihkan (file log aman; tekan r untuk reload)", 2.0)
            elif ch == ord("D"):
                self.confirm_delete = True
            elif ch == ord("c"):
                if current:
                    in_inspect = self.mode == self.MODE_INSPECT
                    if (in_inspect and self.inspect_tab == self.INSPECT_TAB_RES) or (
                        (not in_inspect or self.inspect_tab == self.INSPECT_TAB_SPLIT)
                        and self.focus_pane == self.FOCUS_RES
                    ):
                        payload_dump = format_json_text(current.get("response_payload", {}))
                        res_msg = copy_to_clipboard(payload_dump, self.copy_path)
                        self.set_notice(f"Response JSON {res_msg}")
                    elif (in_inspect and self.inspect_tab == self.INSPECT_TAB_REQ) or (
                        (not in_inspect or self.inspect_tab == self.INSPECT_TAB_SPLIT)
                        and self.focus_pane == self.FOCUS_REQ
                    ):
                        payload_dump = format_json_text(current.get("request_payload", {}))
                        res_msg = copy_to_clipboard(payload_dump, self.copy_path)
                        self.set_notice(f"Request JSON {res_msg}")
                    elif in_inspect and self.inspect_tab == self.INSPECT_TAB_CURL:
                        curl_cmd = format_curl_command(current)
                        res_msg = copy_to_clipboard(curl_cmd, self.copy_path)
                        self.set_notice(f"cURL {res_msg}")
                    else:
                        payload_dump = json.dumps(
                            {
                                "resource_id": current.get("resource_id"),
                                "encounter_id": current.get("encounter_id"),
                                "patient_id": current.get("patient_id"),
                                "request": current.get("request_payload"),
                                "response": current.get("response_payload"),
                            },
                            indent=2,
                            ensure_ascii=False,
                        )
                        res_msg = copy_to_clipboard(payload_dump, self.copy_path)
                        self.set_notice(f"Full JSON {res_msg}")
                    stdscr.clearok(True)
            elif ch == ord("R"):
                if current:
                    payload_dump = format_json_text(current.get("response_payload", {}))
                    res_msg = copy_to_clipboard(payload_dump, self.copy_path)
                    self.set_notice(f"Response JSON {res_msg}")
                    stdscr.clearok(True)
            elif ch == ord("P"):
                if current:
                    payload_dump = format_json_text(current.get("request_payload", {}))
                    res_msg = copy_to_clipboard(payload_dump, self.copy_path)
                    self.set_notice(f"Request JSON {res_msg}")
                    stdscr.clearok(True)
            elif ch == ord("u"):
                if current:
                    curl_cmd = format_curl_command(current)
                    res_msg = copy_to_clipboard(curl_cmd, self.copy_path)
                    self.set_notice(f"cURL {res_msg}")
                    stdscr.clearok(True)
            elif ch == ord("x"):
                self.search_query = ""
                self.filter_resource = "ALL"
                self.filter_status = "ALL"
                self.selected_idx = 0
                self.set_notice("Filters cleared")


def render_static_preview(
    collector: TransactionCollector,
    width: int = 126,
    max_rows: int = 8,
    mode: int = 1,
    initial_status_filter: str = "ALL",
) -> str:
    """Render a plain-text snapshot of the TUI for non-interactive preview/testing."""
    all_items = collector.get_snapshot()
    total = len(all_items)
    sukses = sum(1 for x in all_items if x.get("status") == "Sukses")
    gagal = total - sukses
    items = (
        [x for x in all_items if x.get("status") == initial_status_filter]
        if initial_status_filter != "ALL"
        else all_items
    )

    inner_w = width - 4
    tui_helper = SatuSehatTUI(
        collector=collector,
        base_dir="",
        initial_status_filter=initial_status_filter,
    )
    cols = tui_helper.compute_column_widths(inner_w)
    lines: List[str] = []

    # Top bar
    lines.append("╭" + ("─" * (width - 2)) + "╮")
    left_hdr = f"SATUSEHAT FHIR MONITOR   [1]Split [2]Table [3]Inspect [4]Summary (mode={mode})"
    right_hdr = f"total: {total} | sukses: {sukses} | gagal: {gagal} | filter: ALL/{initial_status_filter}"
    gap = max(2, inner_w - len(left_hdr) - len(right_hdr))
    lines.append("│ " + (left_hdr + (" " * gap) + right_hdr)[:inner_w].ljust(inner_w) + " │")
    lines.append("╰" + ("─" * (width - 2)) + "╯")

    if mode == 4:
        # Summary mode preview
        s_title = "╭─ Ringkasan Transaksi FHIR (Per Resource) "
        lines.append(s_title + ("─" * (width - len(s_title) - 1)) + "╮")
        shdr = (
            f"  {'RESOURCE NAME':<24}  {'TOTAL':>8}  {'SUKSES':>8}  "
            f"{'GAGAL':>8}  {'SUCCESS RATE':>14}  {'LAST ACTIVITY':<20}"
        )
        lines.append("│ " + shdr[:inner_w].ljust(inner_w) + " │")
        lines.append("│ " + ("─" * inner_w) + " │")
        stats: Dict[str, Dict[str, Any]] = {}
        for item in items:
            rn = str(item.get("resource_name", "FHIR"))
            st = stats.setdefault(rn, {"total": 0, "sukses": 0, "gagal": 0, "last": "-"})
            st["total"] += 1
            if item.get("status") == "Sukses":
                st["sukses"] += 1
            else:
                st["gagal"] += 1
            if st["last"] == "-":
                st["last"] = item.get("waktu_kirim", "-")
        for rn, st in sorted(stats.items(), key=lambda kv: kv[1]["total"], reverse=True):
            rate = (st["sukses"] / st["total"] * 100.0) if st["total"] else 0.0
            row_s = (
                f"  {rn:<24}  {st['total']:>8}  {st['sukses']:>8}  "
                f"{st['gagal']:>8}  {rate:>13.1f}%  {st['last']:<20}"
            )
            lines.append("│ " + row_s[:inner_w].ljust(inner_w) + " │")
        lines.append("╰" + ("─" * (width - 2)) + "╯")
        return "\n".join(lines)

    # Table box
    t_title = "╭─ Log Transaksi FHIR "
    lines.append(t_title + ("─" * (width - len(t_title) - 1)) + "╮")

    hdr = (
        "  "
        + trunc("WAKTU KIRIM", cols["waktu"]) + "  "
        + trunc("RESOURCE NAME", cols["resource"]) + "  "
        + trunc("METHOD", cols["method"]) + "  "
        + trunc("STATUS", cols["status"]) + "  "
        + trunc("RESPONSE", cols["response"]) + "  "
        + trunc("RULE", cols["rule"]) + "  "
        + trunc("RESOURCE ID", cols["resource_id"]) + "  "
        + trunc("ENCOUNTER ID", cols["encounter_id"]) + "  "
        + trunc("PATIENT ID", cols["patient_id"])
    )
    lines.append("│ " + hdr[:inner_w].ljust(inner_w) + " │")
    lines.append("│ " + ("─" * inner_w) + " │")

    for idx, item in enumerate(items[:max_rows]):
        prefix = "> " if idx == 0 else "  "
        row_str = (
            f"{prefix}"
            + trunc(item.get("waktu_kirim", "-"), cols["waktu"]) + "  "
            + trunc(item.get("resource_name", "-"), cols["resource"]) + "  "
            + trunc(item.get("method", "-"), cols["method"]) + "  "
            + trunc(item.get("status", "-"), cols["status"]) + "  "
            + trunc(item.get("response", "-"), cols["response"]) + "  "
            + trunc(item.get("rule_number", "-"), cols["rule"]) + "  "
            + trunc(item.get("resource_id", "-"), cols["resource_id"]) + "  "
            + trunc(item.get("encounter_id", "-"), cols["encounter_id"]) + "  "
            + trunc(item.get("patient_id", "-"), cols["patient_id"])
        )
        lines.append("│ " + row_str[:inner_w].ljust(inner_w) + " │")

    lines.append("╰" + ("─" * (width - 2)) + "╯")

    if mode == 1:
        # Split pane preview for row 0
        cur = items[0] if items else {}
        left_w = width // 2
        right_w = width - left_w
        l_title = f"╭─ Request Payload ({cur.get('method', 'POST')} /{cur.get('resource_name', 'FHIR')}) "
        r_title = f"╭─ Response Body ({cur.get('response', '200 OK')}) "
        lines.append(
            l_title + ("─" * max(1, left_w - len(l_title) - 1)) + "╮"
            + r_title + ("─" * max(1, right_w - len(r_title) - 1)) + "╮"
        )

        req_lines = json.dumps(cur.get("request_payload", {}), indent=2, ensure_ascii=False).splitlines()
        res_lines = json.dumps(cur.get("response_payload", {}), indent=2, ensure_ascii=False).splitlines()
        for i in range(6):
            l_txt = req_lines[i] if i < len(req_lines) else ""
            r_txt = res_lines[i] if i < len(res_lines) else ""
            lines.append(
                "│ " + l_txt[: left_w - 4].ljust(left_w - 4) + " │"
                + "│ " + r_txt[: right_w - 4].ljust(right_w - 4) + " │"
            )

        lines.append(
            "╰" + ("─" * (left_w - 2)) + "╯"
            + "╰" + ("─" * (right_w - 2)) + "╯"
        )

    lines.append(
        "  j/k: navigate   enter: inspect   1-4: mode   /: search   f: resource   s: status   e: errors   r: reload   c: copy   R: copy res   P: copy req   u: curl   q: quit"
    )
    return "\n".join(lines)

