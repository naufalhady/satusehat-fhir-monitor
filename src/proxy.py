#!/usr/bin/env python3
"""
Reverse-proxy sidecar for SATUSEHAT FHIR Monitor.

- Zero changes needed in the SIMRS codebase (point the SATUSEHAT_*_URL values at this proxy).
- Forwards requests/responses to the upstream SATUSEHAT API unchanged.
- Writes a sanitised copy of every transaction to daily JSONL files (`<log_dir>/fhir-YYYY-MM-DD.jsonl`).
- Never logs Authorization headers; OAuth secrets/tokens are always redacted.
- Optional PII masking (NIK, names, addresses, phone, e-mail, birth date) in the *log only*.

Security defaults: binds to loopback only, log files are private (0600), request/response size
and connection limits are enforced, TLS verification cannot be disabled against production hosts.

Python 3.10+ (stdlib only).
"""

import sys

if sys.version_info < (3, 10):  # pragma: no cover
    sys.exit("satusehat-monitor requires Python 3.10 or newer.")

import argparse
import datetime
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SRC_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from fhir_extract import build_transaction_record, parse_body_for_log  # noqa: E402

__version__ = "0.2.0"

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}

_HEX_RE = re.compile(rb"^[0-9a-fA-F]{1,8}$")
_NONPROD_HINTS = ("stg", "staging", "dev", "sandbox", "test", "mock", "local")


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def is_nonprod_host(host: str) -> bool:
    """True for loopback or hostnames that look like staging/dev/sandbox endpoints."""
    h = (host or "").lower()
    return is_loopback_host(h) or any(hint in h for hint in _NONPROD_HINTS)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        return None


class _BodyError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class DailyJsonlWriter:
    """Thread-safe daily rotating JSONL writer: private permissions, retention and daily size cap."""

    def __init__(
        self,
        log_dir: str,
        retention_days: int = 14,
        file_mode: int = 0o600,
        max_daily_bytes: int = 0,
    ) -> None:
        self.log_dir = os.path.abspath(log_dir)
        self.retention_days = max(1, int(retention_days))
        self.file_mode = file_mode
        # directory needs +x wherever the file mode grants +r
        self.dir_mode = file_mode | ((file_mode & 0o444) >> 2) | 0o700
        self.max_daily_bytes = max(0, int(max_daily_bytes))
        self._lock = threading.Lock()
        self._last_cleanup_date: Optional[str] = None
        self._cap_warned_for: Optional[str] = None

        created = not os.path.isdir(self.log_dir)
        os.makedirs(self.log_dir, mode=self.dir_mode, exist_ok=True)
        if created:
            os.chmod(self.log_dir, self.dir_mode)
        elif os.stat(self.log_dir).st_mode & 0o007:
            sys.stderr.write(
                f"[satusehat-proxy] WARNING: log directory {self.log_dir} is accessible to 'other' users; "
                f"logs contain health data. Run: chmod o-rwx '{self.log_dir}'\n"
            )
        self._cleanup_old_logs(datetime.date.today().isoformat())

    def current_file_path(self, today_str: Optional[str] = None) -> str:
        day = today_str or datetime.date.today().isoformat()
        return os.path.join(self.log_dir, f"fhir-{day}.jsonl")

    def write_record(self, record: Dict[str, Any]) -> None:
        today_str = datetime.date.today().isoformat()
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        data = line.encode("utf-8")
        with self._lock:
            if self._last_cleanup_date != today_str:
                self._cleanup_old_logs(today_str)
            path = self.current_file_path(today_str)
            existed = os.path.exists(path)
            if self.max_daily_bytes and existed and os.path.getsize(path) + len(data) > self.max_daily_bytes:
                if self._cap_warned_for != today_str:
                    self._cap_warned_for = today_str
                    sys.stderr.write(
                        f"[satusehat-proxy] daily log cap reached ({self.max_daily_bytes} bytes); "
                        "further transactions today are forwarded but NOT logged.\n"
                    )
                return
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags, self.file_mode)
            try:
                if not existed:
                    os.fchmod(fd, self.file_mode)
                os.write(fd, data)
            finally:
                os.close(fd)

    def _cleanup_old_logs(self, today_str: str) -> None:
        self._last_cleanup_date = today_str
        cutoff = datetime.date.today() - datetime.timedelta(days=self.retention_days)
        try:
            for name in os.listdir(self.log_dir):
                if not (name.startswith("fhir-") and name.endswith(".jsonl")):
                    continue
                try:
                    file_date = datetime.date.fromisoformat(name[5:-6])
                except ValueError:
                    continue
                if file_date < cutoff:
                    try:
                        os.remove(os.path.join(self.log_dir, name))
                    except OSError:
                        pass
        except OSError:
            pass


class ProxyConfig:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8999,
        upstream_url: str = "https://api-satusehat-stg.dto.kemkes.go.id",
        log_dir: str = "logs",
        timeout_sec: int = 30,
        retention_days: int = 14,
        log_auth_success: bool = False,
        insecure_tls: bool = False,
        mask_pii: bool = False,
        allow_remote: bool = False,
        max_body_bytes: int = 20 * 1024 * 1024,
        max_logged_body_chars: int = 2 * 1024 * 1024,
        max_connections: int = 64,
        max_daily_log_bytes: int = 512 * 1024 * 1024,
        log_file_mode: int = 0o600,
    ) -> None:
        self.host = host
        self.port = port
        self.upstream_url = upstream_url.rstrip("/")
        self.log_dir = os.path.abspath(log_dir)
        self.timeout_sec = timeout_sec
        self.retention_days = retention_days
        self.log_auth_success = log_auth_success
        self.insecure_tls = insecure_tls
        self.mask_pii = mask_pii
        self.allow_remote = allow_remote
        self.max_body_bytes = max_body_bytes
        self.max_logged_body_chars = max_logged_body_chars
        self.max_connections = max_connections
        self.max_daily_log_bytes = max_daily_log_bytes
        self.log_file_mode = log_file_mode
        self.started_at = time.time()

    @property
    def upstream_host(self) -> str:
        return urlsplit(self.upstream_url).hostname or ""


class SatuSehatProxyServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: Tuple[str, int],
        handler_cls: Any,
        proxy_config: ProxyConfig,
        writer: DailyJsonlWriter,
    ) -> None:
        self.proxy_config = proxy_config
        self.writer = writer
        self.slots = threading.BoundedSemaphore(max(1, proxy_config.max_connections))
        ctx = ssl.create_default_context()
        if proxy_config.insecure_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # guarded by validate_config(): non-production hosts only
        handlers: List[Any] = [_NoRedirectHandler(), urllib.request.HTTPSHandler(context=ctx)]
        if is_loopback_host(proxy_config.upstream_host):
            handlers.append(urllib.request.HTTPHandler())  # plain-HTTP upstream: loopback mocks only
        self.opener = urllib.request.build_opener(*handlers)
        super().__init__(server_address, handler_cls)


def _safe_gunzip(data: bytes, limit: int) -> Optional[bytes]:
    """Decompress gzip with an output cap (protects against decompression bombs)."""
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(data, limit + 1)
    except zlib.error:
        return None
    return out if len(out) <= limit else None


class SatuSehatProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60  # idle/slow-client socket timeout (slowloris protection)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # suppress per-request stderr noise

    def do_GET(self) -> None:
        self._handle_request("GET")

    def do_POST(self) -> None:
        self._handle_request("POST")

    def do_PUT(self) -> None:
        self._handle_request("PUT")

    def do_PATCH(self) -> None:
        self._handle_request("PATCH")

    def do_DELETE(self) -> None:
        self._handle_request("DELETE")

    def do_OPTIONS(self) -> None:
        self._handle_request("OPTIONS")

    # -- request body -----------------------------------------------------------------
    def _read_exact(self, n: int) -> bytes:
        data = self.rfile.read(n)
        if len(data) != n:
            raise _BodyError(400, "Request body shorter than declared")
        return data

    def _read_request_body(self, max_bytes: int) -> bytes:
        transfer_enc = (self.headers.get("Transfer-Encoding") or "").lower()
        try:
            if "chunked" in transfer_enc:
                chunks: List[bytes] = []
                total = 0
                while True:
                    line = self.rfile.readline(1024)
                    if not line:
                        raise _BodyError(400, "Unexpected end of chunked body")
                    size_tok = line.strip().split(b";", 1)[0]
                    if not _HEX_RE.match(size_tok):
                        raise _BodyError(400, "Malformed chunk size")
                    size = int(size_tok, 16)
                    if size == 0:
                        for _ in range(100):  # drain trailers, bounded
                            trailer = self.rfile.readline(1024)
                            if not trailer or trailer in (b"\r\n", b"\n"):
                                break
                        break
                    total += size
                    if total > max_bytes:
                        raise _BodyError(413, f"Request body exceeds {max_bytes} bytes")
                    chunks.append(self._read_exact(size))
                    self.rfile.read(2)  # trailing CRLF
                return b"".join(chunks)

            content_len = self.headers.get("Content-Length")
            if content_len is not None:
                cl = content_len.strip()
                if not (cl.isascii() and cl.isdigit()):
                    raise _BodyError(400, "Invalid Content-Length")
                length = int(cl)
                if length > max_bytes:
                    raise _BodyError(413, f"Request body exceeds {max_bytes} bytes")
                if length > 0:
                    return self._read_exact(length)
        except (socket.timeout, TimeoutError):
            raise _BodyError(408, "Timed out reading request body") from None
        return b""

    @staticmethod
    def _read_limited(fp: Any, limit: int) -> bytes:
        data = fp.read(limit + 1)
        if len(data) > limit:
            raise _BodyError(502, f"Upstream response exceeds {limit} bytes")
        return data

    # -- responses --------------------------------------------------------------------
    def _send_json_response(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/fhir+json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass  # client already went away
        self.close_connection = True

    @staticmethod
    def _outcome(code: str, diagnostics: str) -> Dict[str, Any]:
        return {
            "resourceType": "OperationOutcome",
            "issue": [{"severity": "error", "code": code, "diagnostics": diagnostics}],
        }

    def _handle_request(self, method: str) -> None:
        srv: SatuSehatProxyServer = self.server  # type: ignore[assignment]
        cfg = srv.proxy_config

        if method == "GET" and self.path.split("?", 1)[0] == "/_health":
            self._send_json_response(
                200,
                {
                    "status": "ok",
                    "version": __version__,
                    "upstream_host": cfg.upstream_host,
                    "pii_masking": cfg.mask_pii,
                    "uptime_sec": int(time.time() - cfg.started_at),
                },
            )
            return

        if not srv.slots.acquire(blocking=False):
            self._send_json_response(503, self._outcome("throttled", "Proxy is at max_connections"))
            return
        try:
            self._proxy(method, srv, cfg)
        finally:
            srv.slots.release()

    def _proxy(self, method: str, srv: SatuSehatProxyServer, cfg: ProxyConfig) -> None:
        t0 = time.monotonic()
        try:
            req_bytes = self._read_request_body(cfg.max_body_bytes)
        except _BodyError as e:
            self._send_json_response(e.status, self._outcome("invalid", e.message))
            return

        req_content_type = self.headers.get("Content-Type", "")
        target_url = cfg.upstream_url + (self.path if self.path.startswith("/") else "/" + self.path)

        fwd_headers: Dict[str, str] = {
            k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP_HEADERS
        }
        req_data_arg: Optional[bytes] = req_bytes if (req_bytes or method in ("POST", "PUT", "PATCH")) else None
        upstream_req = urllib.request.Request(  # noqa: S310 - scheme validated in validate_config()
            target_url, data=req_data_arg, headers=fwd_headers, method=method
        )

        def gateway_error(status: int, reason: str, code: str, diag: str) -> None:
            outcome = self._outcome(code, diag)
            self._send_json_response(status, outcome)
            self._record_transaction(
                srv, method, target_url, status, reason, int((time.monotonic() - t0) * 1000),
                req_bytes, req_content_type, json.dumps(outcome).encode("utf-8"), "",
                "application/fhir+json", diag,
            )

        try:
            with srv.opener.open(upstream_req, timeout=cfg.timeout_sec) as resp:  # nosec B310
                http_status = resp.status
                reason = resp.reason or ""
                res_headers = list(resp.headers.items())
                res_raw_bytes = self._read_limited(resp, cfg.max_body_bytes)
        except urllib.error.HTTPError as e:
            http_status = e.code
            reason = str(e.reason or "")
            res_headers = list(e.headers.items()) if e.headers else []
            try:
                res_raw_bytes = self._read_limited(e, cfg.max_body_bytes)
            except _BodyError as be:
                gateway_error(502, "Bad Gateway", "too-costly", be.message)
                return
            except Exception:
                res_raw_bytes = b""
        except _BodyError as be:
            gateway_error(502, "Bad Gateway", "too-costly", be.message)
            return
        except (socket.timeout, TimeoutError) as e:
            gateway_error(504, "Gateway Timeout", "timeout",
                          f"Upstream SATUSEHAT timeout after {cfg.timeout_sec}s: {e}")
            return
        except urllib.error.URLError as e:
            is_timeout = isinstance(e.reason, (socket.timeout, TimeoutError)) or "timed out" in str(e.reason).lower()
            if is_timeout:
                gateway_error(504, "Gateway Timeout", "timeout", f"Upstream SATUSEHAT error: {e.reason}")
            else:
                gateway_error(502, "Bad Gateway", "exception", f"Upstream SATUSEHAT error: {e.reason}")
            return
        except Exception as e:  # noqa: BLE001 - last-resort: never leave the client hanging
            gateway_error(502, "Bad Gateway", "exception", f"Proxy error: {e}")
            return

        latency_ms = int((time.monotonic() - t0) * 1000)

        res_content_encoding = ""
        res_content_type = ""
        try:
            self.send_response(http_status, reason)
            for k, v in res_headers:
                kl = k.lower()
                if kl in _HOP_BY_HOP_HEADERS:
                    continue
                if kl == "content-encoding":
                    res_content_encoding = v.lower()
                elif kl == "content-type":
                    res_content_type = v.lower()
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(res_raw_bytes)))
            self.send_header("Connection", "close")
            self.end_headers()
            if res_raw_bytes:
                self.wfile.write(res_raw_bytes)
        except OSError:
            pass  # client disconnected mid-response; the upstream transaction is still logged below
        self.close_connection = True

        self._record_transaction(
            srv, method, target_url, http_status, reason, latency_ms, req_bytes, req_content_type,
            res_raw_bytes, res_content_encoding, res_content_type,
        )

    def _record_transaction(
        self,
        srv: SatuSehatProxyServer,
        method: str,
        target_url: str,
        http_status: int,
        reason: str,
        latency_ms: int,
        req_bytes: bytes,
        req_content_type: str,
        res_bytes: bytes,
        res_content_encoding: str,
        res_content_type: str,
        res_raw_text: str = "",
    ) -> None:
        cfg = srv.proxy_config
        is_oauth = "/oauth2/" in self.path.lower()
        if is_oauth and 200 <= http_status < 300 and not cfg.log_auth_success:
            return

        log_res_bytes = res_bytes
        if "gzip" in res_content_encoding and res_bytes:
            unzipped = _safe_gunzip(res_bytes, cfg.max_body_bytes)
            if unzipped is not None:
                log_res_bytes = unzipped

        req_parsed, _ = parse_body_for_log(req_bytes, req_content_type)
        res_parsed, parsed_res_text = parse_body_for_log(log_res_bytes, res_content_type)

        try:
            rec = build_transaction_record(
                method=method,
                path=self.path,
                upstream_url=target_url,
                http_status=http_status,
                reason=reason,
                latency_ms=latency_ms,
                req_data=req_parsed,
                res_data=res_parsed,
                res_raw_text=res_raw_text or parsed_res_text,
                mask_pii=cfg.mask_pii,
                max_payload_chars=cfg.max_logged_body_chars,
            )
            srv.writer.write_record(rec)
        except Exception as e:  # noqa: BLE001 - logging must never break forwarding
            sys.stderr.write(f"[satusehat-proxy] failed writing log: {type(e).__name__}: {e}\n")


# ------------------------------------------------------------------------------------
# configuration
# ------------------------------------------------------------------------------------

def load_config_file() -> Dict[str, Any]:
    cfg_path = os.path.join(BASE_DIR, "config.json")
    if os.path.isfile(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except (OSError, ValueError):
            sys.stderr.write("[satusehat-proxy] WARNING: config.json unreadable/invalid; using defaults.\n")
    return {}


def _as_bool(val: Any) -> bool:
    return str(val).strip().lower() in ("1", "true", "yes", "on")


def validate_config(cfg: ProxyConfig) -> None:
    """Raise ValueError with a human-readable message when the configuration is unsafe/invalid."""
    if not (1 <= cfg.port <= 65535):
        raise ValueError(f"port out of range: {cfg.port}")
    if not (1 <= cfg.timeout_sec <= 600):
        raise ValueError("upstream timeout must be between 1 and 600 seconds")
    if not (1 <= cfg.retention_days <= 3650):
        raise ValueError("retention_days must be between 1 and 3650")
    if cfg.max_body_bytes < 1024:
        raise ValueError("max_body_mb is too small")

    parts = urlsplit(cfg.upstream_url)
    if not parts.hostname or parts.query or parts.fragment:
        raise ValueError(f"invalid upstream URL: {cfg.upstream_url!r}")
    if parts.scheme != "https" and not (parts.scheme == "http" and is_loopback_host(parts.hostname)):
        raise ValueError("upstream must be https:// (plain http:// is only accepted for loopback test servers)")

    if not is_loopback_host(cfg.host) and not cfg.allow_remote:
        raise ValueError(
            f"refusing to bind to non-loopback address {cfg.host!r}: the proxy has no authentication and "
            "its logs contain health data. Use 127.0.0.1, or pass --allow-remote and protect the port with "
            "a firewall / private network / TLS tunnel."
        )
    if cfg.insecure_tls and not is_nonprod_host(parts.hostname):
        raise ValueError("--insecure (TLS verification off) is refused for production-looking upstream hosts")


def build_proxy_config(args: argparse.Namespace) -> ProxyConfig:
    file_cfg = load_config_file()

    def pick(cli_val: Any, env_key: str, cfg_key: str, default: Any) -> Any:
        if cli_val is not None:
            return cli_val
        env_val = os.environ.get(env_key)
        if env_val not in (None, ""):
            return env_val
        if cfg_key in file_cfg and file_cfg[cfg_key] not in (None, ""):
            return file_cfg[cfg_key]
        return default

    def pick_bool(cli_flag: bool, env_key: str, cfg_key: str) -> bool:
        if cli_flag:
            return True
        env_val = os.environ.get(env_key, "")
        if env_val != "":
            return _as_bool(env_val)
        return _as_bool(file_cfg.get(cfg_key, False))

    host = str(pick(args.host, "SATUSEHAT_PROXY_HOST", "proxy_host", "127.0.0.1"))
    upstream = str(pick(args.upstream, "SATUSEHAT_UPSTREAM_URL", "upstream_url",
                        "https://api-satusehat-stg.dto.kemkes.go.id"))
    raw_log_dir = str(pick(args.log_dir, "SATUSEHAT_LOG_DIR", "log_dir", "logs"))
    log_dir = raw_log_dir if os.path.isabs(raw_log_dir) else os.path.join(BASE_DIR, raw_log_dir)

    mask_mode = str(pick(args.mask_pii, "SATUSEHAT_MASK_PII", "mask_pii", "auto")).strip().lower()
    if mask_mode not in ("auto", "on", "off", "true", "false", "1", "0"):
        raise ValueError("mask_pii must be one of: auto, on, off")
    up_host = urlsplit(upstream.rstrip("/")).hostname or ""
    if mask_mode == "auto":
        mask_pii = not is_nonprod_host(up_host)  # production upstream => mask by default
    else:
        mask_pii = mask_mode in ("on", "true", "1")

    try:
        file_mode = int(str(pick(None, "SATUSEHAT_LOG_FILE_MODE", "log_file_mode", "600")), 8)
    except ValueError:
        raise ValueError("log_file_mode must be an octal string such as 600 or 640") from None
    if (file_mode & 0o007) or (file_mode & 0o600) != 0o600:
        raise ValueError("log_file_mode must give the owner rw and give 'other' no access (600 or 640)")

    return ProxyConfig(
        host=host,
        port=int(pick(args.port, "SATUSEHAT_PROXY_PORT", "proxy_port", 8999)),
        upstream_url=upstream,
        log_dir=log_dir,
        timeout_sec=int(pick(args.timeout, "SATUSEHAT_UPSTREAM_TIMEOUT", "upstream_timeout_sec", 30)),
        retention_days=int(pick(args.retention_days, "SATUSEHAT_RETENTION_DAYS", "retention_days", 14)),
        log_auth_success=pick_bool(args.log_auth, "SATUSEHAT_LOG_AUTH_SUCCESS", "log_auth_success"),
        insecure_tls=pick_bool(args.insecure, "SATUSEHAT_INSECURE", "insecure_tls"),
        mask_pii=mask_pii,
        allow_remote=bool(args.allow_remote),
        max_body_bytes=int(float(pick(None, "SATUSEHAT_MAX_BODY_MB", "max_body_mb", 20)) * 1024 * 1024),
        max_logged_body_chars=int(float(pick(None, "SATUSEHAT_MAX_LOGGED_BODY_KB", "max_logged_body_kb", 2048)) * 1024),
        max_connections=int(pick(None, "SATUSEHAT_MAX_CONNECTIONS", "max_connections", 64)),
        max_daily_log_bytes=int(float(pick(None, "SATUSEHAT_MAX_DAILY_LOG_MB", "max_daily_log_mb", 512)) * 1024 * 1024),
        log_file_mode=file_mode,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="SATUSEHAT HTTP-to-HTTPS Reverse Proxy Sidecar")
    ap.add_argument("--host", default=None, help="Bind host (default: 127.0.0.1, loopback only)")
    ap.add_argument("--port", type=int, default=None, help="Bind port (default: 8999)")
    ap.add_argument("--upstream", default=None, help="Upstream SATUSEHAT base origin (https)")
    ap.add_argument("--log-dir", default=None, help="Directory for daily fhir-YYYY-MM-DD.jsonl logs")
    ap.add_argument("--timeout", type=int, default=None, help="Upstream timeout in seconds")
    ap.add_argument("--retention-days", type=int, default=None, help="Log retention in days")
    ap.add_argument("--mask-pii", choices=["auto", "on", "off"], default=None,
                    help="Mask personal data in logs. auto (default): on for production upstream, off for staging")
    ap.add_argument("--allow-remote", action="store_true",
                    help="Allow binding to a non-loopback address (the proxy has NO authentication)")
    ap.add_argument("--log-auth", action="store_true", help="Also log successful /oauth2/ calls (redacted)")
    ap.add_argument("--insecure", action="store_true",
                    help="Disable upstream TLS verification (staging/loopback hosts only)")
    ap.add_argument("--version", action="version", version=f"satusehat-proxy {__version__}")
    args = ap.parse_args()

    try:
        cfg = build_proxy_config(args)
        validate_config(cfg)
        writer = DailyJsonlWriter(
            log_dir=cfg.log_dir,
            retention_days=cfg.retention_days,
            file_mode=cfg.log_file_mode,
            max_daily_bytes=cfg.max_daily_log_bytes,
        )
    except (ValueError, OSError) as e:
        sys.stderr.write(f"[satusehat-proxy] configuration error: {e}\n")
        return 2

    if cfg.insecure_tls:
        sys.stderr.write("[satusehat-proxy] WARNING: TLS verification to upstream is DISABLED (--insecure).\n")
    if not cfg.mask_pii:
        sys.stderr.write(
            "[satusehat-proxy] NOTICE: PII masking is OFF - logs will contain full patient data "
            "(treat the log directory as health data under UU PDP No. 27/2022).\n"
        )
    if cfg.allow_remote and not is_loopback_host(cfg.host):
        sys.stderr.write("[satusehat-proxy] WARNING: listening on a non-loopback address WITHOUT authentication or TLS.\n")

    server = SatuSehatProxyServer((cfg.host, cfg.port), SatuSehatProxyHandler, cfg, writer)

    def _shutdown_handler(signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)

    sys.stdout.write(
        f"[satusehat-proxy] v{__version__} listening on http://{cfg.host}:{cfg.port} -> {cfg.upstream_url} "
        f"(logs: {cfg.log_dir}, pii-masking: {'ON' if cfg.mask_pii else 'OFF'})\n"
    )
    sys.stdout.flush()

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
