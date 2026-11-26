import argparse
import gzip
import http.client
import json
import os
import socket
import stat
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import proxy


class MockUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    last = {}

    def log_message(self, *a):
        pass

    def _reply(self, code, payload, extra=None):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/fhir+json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n)
        MockUpstream.last = {"path": self.path, "auth": self.headers.get("Authorization"), "body": raw}
        if "/oauth2/" in self.path:
            return self._reply(401, {"error": "invalid_client", "error_description": "bad"})
        if self.path.endswith("/Bad"):
            return self._reply(400, {"resourceType": "OperationOutcome", "issue": [{
                "severity": "error", "code": "invalid",
                "details": {"text": "Rule Number: 20002 problem"}, "expression": ["Patient.name"]}]})
        return self._reply(201, {"resourceType": "Patient", "id": "abc"})

    def do_GET(self):
        self._reply(200, {"resourceType": "Bundle", "entry": [{"resource": {"resourceType": "Patient", "id": "p1"}}]})


def start(handler, port=0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class ProxyCase(unittest.TestCase):
    mask = False
    max_body = 1024 * 1024
    max_log_chars = 0

    @classmethod
    def setUpClass(cls):
        cls.up = start(MockUpstream)
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = proxy.ProxyConfig(
            upstream_url=f"http://127.0.0.1:{cls.up.server_address[1]}",
            log_dir=os.path.join(cls.tmp.name, "logs"), mask_pii=cls.mask,
            max_body_bytes=cls.max_body, max_logged_body_chars=cls.max_log_chars, timeout_sec=5,
        )
        proxy.validate_config(cfg)
        cls.writer = proxy.DailyJsonlWriter(cfg.log_dir, 14, cfg.log_file_mode, 0)
        cls.px = proxy.SatuSehatProxyServer(("127.0.0.1", 0), proxy.SatuSehatProxyHandler, cfg, cls.writer)
        threading.Thread(target=cls.px.serve_forever, daemon=True).start()
        cls.port = cls.px.server_address[1]

    @classmethod
    def tearDownClass(cls):
        for srv in (cls.px, cls.up):
            srv.shutdown()
            srv.server_close()
        cls.tmp.cleanup()

    def req(self, method, path, body=None, headers=None, wait_log=True):
        """Send a request; for forwarded calls also wait until the proxy has written its log line
        (the proxy logs *after* answering the client, so reading the log immediately would race).
        Pass wait_log=False for calls the proxy itself rejects (nothing is forwarded or logged)."""
        before = len(self.records())
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        forwarded = wait_log and path != "/_health"
        deadline = time.time() + 3
        while forwarded and time.time() < deadline and len(self.records()) <= before:
            time.sleep(0.01)
        return r.status, data

    def records(self):
        p = self.writer.current_file_path()
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]


class TestForwardingAndLogging(ProxyCase):
    def test_forward_is_transparent_and_logged(self):
        payload = json.dumps({"resourceType": "Patient", "name": [{"text": "Budi Santoso"}]}).encode()
        status, data = self.req("POST", "/fhir-r4/v1/Patient", payload,
                                {"Authorization": "Bearer SUPERSECRETTOKEN123", "Content-Type": "application/fhir+json"})
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(data)["id"], "abc")
        self.assertEqual(MockUpstream.last["body"], payload)                       # forwarded byte-for-byte
        self.assertEqual(MockUpstream.last["auth"], "Bearer SUPERSECRETTOKEN123")   # auth still forwarded
        rec = self.records()[-1]
        self.assertEqual(rec["status"], "Sukses")
        self.assertNotIn("SUPERSECRETTOKEN123", json.dumps(rec))                    # ...but never logged

    def test_error_rule_extracted(self):
        status, _ = self.req("POST", "/fhir-r4/v1/Bad", b"{}", {"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        rec = self.records()[-1]
        self.assertEqual((rec["status"], rec["rule_number"]), ("Gagal", "20002"))

    def test_oauth_secret_redacted_in_failed_call(self):
        body = b"client_id=abc&client_secret=TOPSECRETVALUE&grant_type=client_credentials"
        status, _ = self.req("POST", "/oauth2/v1/accesstoken?grant_type=client_credentials", body,
                             {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 401)
        self.assertNotIn("TOPSECRETVALUE", json.dumps(self.records()[-1]))

    def test_health_does_not_leak_paths(self):
        status, data = self.req("GET", "/_health")
        self.assertEqual(status, 200)
        txt = data.decode()
        self.assertNotIn(self.tmp.name, txt)
        self.assertNotIn("log_dir", txt)

    def test_log_permissions_private(self):
        self.req("GET", "/fhir-r4/v1/Patient")
        self.assertEqual(stat.S_IMODE(os.stat(self.writer.current_file_path()).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.writer.log_dir).st_mode) & 0o077, 0)


class TestLimitsAndMalformed(ProxyCase):
    max_body = 2048

    def raw(self, data):
        """Send raw bytes, return the HTTP status line."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(data)
            try:
                return s.recv(200).split(b"\r\n")[0]
            except ConnectionResetError:
                return b""

    def test_oversize_body_rejected_413(self):
        status, _ = self.req("POST", "/fhir-r4/v1/Patient", b"x" * 5000, wait_log=False)
        self.assertEqual(status, 413)

    def test_invalid_content_length_400(self):
        self.assertIn(b" 400 ", self.raw(b"POST /fhir-r4/v1/Patient HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n"))

    def test_negative_and_underscore_lengths_rejected(self):
        for bad in (b"-5", b"1_0", b"+3"):
            self.assertIn(b" 400 ", self.raw(b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: " + bad + b"\r\n\r\n"), bad)

    def test_malformed_chunk_size_400(self):
        self.assertIn(b" 400 ", self.raw(b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nabc\r\n0\r\n\r\n"))

    def test_oversize_chunked_413(self):
        self.assertIn(b" 413 ", self.raw(b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + b"1388\r\n" + b"a" * 5000 + b"\r\n0\r\n\r\n"))

    def test_proxy_survives_after_bad_requests(self):
        status, _ = self.req("GET", "/fhir-r4/v1/Patient")
        self.assertEqual(status, 200)


class TestMasking(ProxyCase):
    mask = True

    def test_log_masked_but_forward_untouched(self):
        payload = json.dumps({"resourceType": "Patient", "name": [{"text": "Budi Santoso"}],
                              "identifier": [{"system": "https://fhir.kemkes.go.id/id/nik", "value": "3374012345678901"}]}).encode()
        self.req("POST", "/fhir-r4/v1/Patient?name=Budi", payload, {"Content-Type": "application/fhir+json"})
        self.assertEqual(MockUpstream.last["body"], payload)
        self.assertEqual(MockUpstream.last["path"], "/fhir-r4/v1/Patient?name=Budi")
        with open(self.writer.current_file_path(), encoding="utf-8") as f:
            line = f.read()
        for raw in ("Budi", "3374012345678901"):
            self.assertNotIn(raw, line)
        self.assertTrue(self.records()[-1]["pii_masked"])


class TestPayloadCap(ProxyCase):
    max_log_chars = 300

    def test_big_payload_truncated_in_log_only(self):
        big = json.dumps({"resourceType": "Bundle", "entry": ["y" * 100] * 50}).encode()
        status, _ = self.req("POST", "/fhir-r4/v1/Bundle", big, {"Content-Type": "application/json"})
        self.assertEqual(status, 201)
        self.assertEqual(MockUpstream.last["body"], big)
        self.assertTrue(self.records()[-1]["request_payload"]["_truncated"])


class TestConfigGuards(unittest.TestCase):
    def cfg(self, **kw):
        return proxy.ProxyConfig(**kw)

    def test_non_loopback_bind_refused(self):
        with self.assertRaises(ValueError):
            proxy.validate_config(self.cfg(host="0.0.0.0"))

    def test_non_loopback_allowed_with_flag(self):
        proxy.validate_config(self.cfg(host="0.0.0.0", allow_remote=True))

    def test_insecure_refused_for_production(self):
        with self.assertRaises(ValueError):
            proxy.validate_config(self.cfg(upstream_url="https://api-satusehat.dto.kemkes.go.id", insecure_tls=True))

    def test_insecure_ok_for_staging(self):
        proxy.validate_config(self.cfg(insecure_tls=True))

    def test_plain_http_only_for_loopback(self):
        with self.assertRaises(ValueError):
            proxy.validate_config(self.cfg(upstream_url="http://api-satusehat.dto.kemkes.go.id"))
        proxy.validate_config(self.cfg(upstream_url="http://127.0.0.1:9"))

    def test_bad_port(self):
        with self.assertRaises(ValueError):
            proxy.validate_config(self.cfg(port=70000))

    def test_mask_auto_follows_upstream(self):
        def build(upstream):
            ns = argparse.Namespace(host=None, port=None, upstream=upstream, log_dir=None, timeout=None,
                                    retention_days=None, mask_pii=None, allow_remote=False,
                                    log_auth=False, insecure=False)
            return proxy.build_proxy_config(ns).mask_pii
        old = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("SATUSEHAT_")}
        try:
            self.assertFalse(build("https://api-satusehat-stg.dto.kemkes.go.id"))
            self.assertTrue(build("https://api-satusehat.dto.kemkes.go.id"))
        finally:
            os.environ.update(old)


class TestWriter(unittest.TestCase):
    def test_daily_cap_stops_logging(self):
        with tempfile.TemporaryDirectory() as d:
            w = proxy.DailyJsonlWriter(os.path.join(d, "l"), 14, 0o600, max_daily_bytes=300)
            for i in range(20):
                w.write_record({"id": str(i), "pad": "z" * 50})
            self.assertLessEqual(os.path.getsize(w.current_file_path()), 300)

    def test_gunzip_bomb_capped(self):
        bomb = gzip.compress(b"0" * 5_000_000)
        self.assertIsNone(proxy._safe_gunzip(bomb, 1_000_000))
        self.assertEqual(proxy._safe_gunzip(gzip.compress(b"ok"), 1000), b"ok")


if __name__ == "__main__":
    unittest.main()
