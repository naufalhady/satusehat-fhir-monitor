#!/usr/bin/env python3
"""
Zero-fabrication FHIR R4 metadata & error extraction helpers for SATUSEHAT Proxy and TUI.

Also contains the log-sanitising layer:
  * secret redaction  (always on)  - tokens, client secrets, passwords, Bearer strings
  * PII masking       (optional)   - NIK, names, addresses, phone, e-mail, birth date

Python 3.10+ (stdlib only).
"""

import datetime
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote


_REG_ID_RE = re.compile(r"\b(R(?:RI|RJ|UGD|IGD)\d+)\b", re.IGNORECASE)
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SENSITIVE_KEYS = {
    "client_secret",
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "password",
    "secret",
    "api_key",
    "apikey",
    "x-api-key",
    "authorization",
}
REDACTED = "***REDACTED***"

# Secret-looking fragments inside free text / form bodies that failed to parse as JSON.
_SECRET_TEXT_RE = re.compile(
    r"(?i)\b(client_secret|access_token|refresh_token|id_token|password|api[_-]?key)=([^&\s\"']+)"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=\-]{8,}")

# PII patterns used when masking is enabled.
_NIK_RE = re.compile(r"(?<!\d)\d{16}(?!\d)")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?62|0)8\d{8,11}(?!\d)")
_PERSON_REF_RE = re.compile(r"(?:^|/)(?:Patient|Practitioner|RelatedPerson)/|^urn:uuid:", re.IGNORECASE)
# Identifier systems whose *value* is personal (NIK, KK, passport, MRN, ...).
# IHS numbers (patient_id) are deliberately NOT included: they are what developers debug with.
_SENSITIVE_IDENT_TOKENS = {"nik", "kk", "ktp", "paspor", "passport", "mrn", "sim", "npwp", "bpjs"}
_QUERY_PII_KEYS = {
    "name", "family", "given", "birthdate", "telecom", "phone", "email", "address",
    "address-city", "address-postalcode",
}

_STATUS_LABELS: Dict[int, str] = {
    200: "200 OK",
    201: "201 Created",
    202: "202 Accepted",
    204: "204 NoCont",
    400: "400 Bad Req",
    401: "401 Unauth",
    403: "403 Forbid",
    404: "404 NotFound",
    405: "405 MethodNA",
    408: "408 Timeout",
    409: "409 Conflict",
    413: "413 TooLarge",
    415: "415 BadMedia",
    422: "422 Unproc",
    429: "429 RateLim",
    500: "500 SrvErr",
    502: "502 BadGW",
    503: "503 Unavail",
    504: "504 Timeout",
}


def clean_ref(ref: Any, prefix: str) -> str:
    """Strip 'Patient/', 'Encounter/', 'urn:uuid:', or URL prefix from FHIR reference."""
    if not isinstance(ref, str) or not ref.strip():
        return ""
    s = ref.strip()
    if s.startswith("urn:uuid:"):
        return s[9:].strip()
    pattern = rf"^(?:https?://[^/]+/\S*/)?{re.escape(prefix)}/"
    cleaned = re.sub(pattern, "", s, flags=re.IGNORECASE)
    return cleaned.strip()


def http_status_label(code: int, reason: str = "") -> str:
    """Return a concise status string fitting the 12-character TUI column."""
    if code == 0:
        return "0 ConnErr"
    if code in _STATUS_LABELS:
        return _STATUS_LABELS[code]
    short_reason = (reason or "").strip()[:8]
    return f"{code} {short_reason}".strip() if short_reason else str(code)


def detect_resource_from_path(path: str) -> Tuple[str, str]:
    """
    Extract (resource_name, url_resource_id) from a SATUSEHAT request path.
    Supports /fhir-r4/v1/..., /consent/v1/..., /kfa-v2/..., /oauth2/v1/...
    """
    clean_path = (path or "").split("?", 1)[0].strip("/")
    if not clean_path:
        return "FHIR", "-"

    parts = [p for p in clean_path.split("/") if p]
    low_parts = [p.lower() for p in parts]

    for prefix in (("fhir-r4", "v1"), ("consent", "v1"), ("kfa-v2",), ("oauth2", "v1")):
        plen = len(prefix)
        for i in range(len(low_parts) - plen + 1):
            if tuple(low_parts[i : i + plen]) == prefix:
                rem = parts[i + plen :]
                if prefix[0] == "oauth2":
                    return "OAuth2", "-"
                if prefix[0] == "kfa-v2":
                    res_name = f"KFA/{rem[0]}" if rem else "KFA"
                    return res_name, (rem[1] if len(rem) >= 2 else "-")
                if not rem:
                    return ("Bundle" if prefix[0] == "fhir-r4" else prefix[0].title()), "-"
                res_name = rem[0]
                res_id = rem[1] if len(rem) >= 2 and not rem[1].startswith("_") else "-"
                return res_name, res_id

    if len(parts) == 1:
        return parts[0], "-"
    if _UUID_RE.match(parts[-1]) or parts[-1].isdigit():
        return parts[-2], parts[-1]
    return parts[-1], "-"


def extract_rule_and_error(
    res_obj: Any, http_status: int = 0, raw_text: str = ""
) -> Tuple[str, str]:
    """
    Extract SATUSEHAT Rule Number (e.g. '20002', '10377') and readable error summary
    from an OperationOutcome, Apigee Fault, or raw HTTP error response.
    """
    if isinstance(res_obj, dict):
        if "respons" in res_obj and isinstance(res_obj["respons"], dict):
            res_obj = res_obj["respons"]
        elif "error" in res_obj and isinstance(res_obj["error"], dict):
            res_obj = res_obj["error"]

        rule_number = "-"
        summaries: List[str] = []

        if (
            res_obj.get("resourceType") == "OperationOutcome"
            or isinstance(res_obj.get("issue"), list)
        ) and isinstance(res_obj.get("issue"), list):
            for issue in res_obj["issue"]:
                if not isinstance(issue, dict):
                    continue
                code = str(issue.get("code") or "")
                details = issue.get("details") if isinstance(issue.get("details"), dict) else {}
                details_text = str(details.get("text") or "")
                coding = details.get("coding") if isinstance(details.get("coding"), list) else []
                coding_code = (
                    str(coding[0].get("code"))
                    if coding and isinstance(coding[0], dict) and coding[0].get("code")
                    else ""
                )
                diagnostics = str(issue.get("diagnostics") or "")
                expr_list = issue.get("expression") or issue.get("location") or []
                loc = str(expr_list[0]) if isinstance(expr_list, list) and expr_list else ""

                if rule_number == "-":
                    m = re.search(
                        r"Rule\s*(?:Number)?\s*[:#]?\s*(\d{4,6})",
                        details_text + " " + diagnostics,
                        re.IGNORECASE,
                    )
                    if m:
                        rule_number = m.group(1)
                    elif coding_code:
                        rule_number = coding_code
                    else:
                        m2 = re.search(r"\b(\d{4,6})\b", details_text)
                        if m2:
                            rule_number = m2.group(1)
                        elif code:
                            rule_number = code

                parts: List[str] = []
                if loc:
                    parts.append(f"[{loc}]")
                if details_text:
                    parts.append(details_text)
                if diagnostics and diagnostics not in details_text:
                    parts.append(diagnostics)
                if parts:
                    summaries.append(" - ".join(parts))

            if rule_number == "-" and http_status >= 400:
                rule_number = str(http_status)
            return rule_number, " | ".join(summaries)

        fault = res_obj.get("Fault") or res_obj.get("fault")
        if isinstance(fault, dict):
            detail = fault.get("detail") if isinstance(fault.get("detail"), dict) else {}
            rule_number = str(detail.get("errorcode") or fault.get("code") or "AUTH")
            fault_str = str(fault.get("faultstring") or "Authentication / Gateway Fault")
            return rule_number, fault_str

        if "error_description" in res_obj or "Error" in res_obj:
            err_code = str(res_obj.get("error") or res_obj.get("ErrorCode") or http_status or "AUTH")
            err_desc = str(
                res_obj.get("error_description") or res_obj.get("Error") or ""
            )
            return err_code, err_desc

        if http_status >= 400:
            msg = str(res_obj.get("message") or res_obj.get("error") or "")
            return str(http_status), msg[:240]

    if http_status == 0:
        low = (raw_text or "").lower()
        rule = "TIMEOUT" if "timeout" in low or "timed out" in low else "NET_ERR"
        return rule, (raw_text or "Connection failed")[:240]

    if http_status >= 400:
        cleaned = " ".join((raw_text or "").split())
        return str(http_status), cleaned[:240]

    return "-", ""


def _extract_reg_id_from_doc(doc: Dict[str, Any]) -> str:
    identifiers = doc.get("identifier")
    if not isinstance(identifiers, list):
        return "-"
    for ident in identifiers:
        if not isinstance(ident, dict):
            continue
        val = str(ident.get("value") or "").strip()
        if not val:
            continue
        m = _REG_ID_RE.search(val)
        if m:
            return m.group(1).upper()
        system = str(ident.get("system") or "").lower()
        if "encounter" in system:
            return val
    return "-"


def extract_fhir_fields(
    doc: Any, fallback_resource: str = ""
) -> Dict[str, str]:
    """
    Inspect a real FHIR JSON payload/response (including Bundle) and extract:
    resource_name, resource_id, encounter_id, patient_id, patient_name, id_registrasi.
    """
    result = {
        "resource_name": fallback_resource or "FHIR",
        "resource_id": "-",
        "encounter_id": "-",
        "patient_id": "-",
        "patient_name": "-",
        "id_registrasi": "-",
    }
    if not isinstance(doc, dict):
        return result

    res_type = doc.get("resourceType")
    if isinstance(res_type, str) and res_type != "OperationOutcome":
        if res_type != "Bundle" or not fallback_resource:
            result["resource_name"] = res_type
        if doc.get("id"):
            result["resource_id"] = str(doc["id"])

    for field in ("subject", "patient", "for"):
        sub = doc.get(field)
        if isinstance(sub, dict):
            ref = sub.get("reference")
            if ref:
                pid = clean_ref(ref, "Patient")
                if pid and not pid.startswith("Practitioner/"):
                    result["patient_id"] = pid
            disp = sub.get("display")
            if disp and isinstance(disp, str) and disp.strip():
                result["patient_name"] = disp.strip()

    for field in ("encounter", "context"):
        enc = doc.get(field)
        if isinstance(enc, dict):
            ref = enc.get("reference")
            if ref:
                eid = clean_ref(ref, "Encounter")
                if eid:
                    result["encounter_id"] = eid

    if result["resource_name"] == "Encounter" and result["resource_id"] != "-":
        result["encounter_id"] = result["resource_id"]
    elif result["resource_name"] == "Patient" and result["resource_id"] != "-":
        result["patient_id"] = result["resource_id"]
        if result["patient_name"] == "-" and isinstance(doc.get("name"), list) and doc["name"]:
            first_name = doc["name"][0]
            if isinstance(first_name, dict) and first_name.get("text"):
                result["patient_name"] = str(first_name["text"])

    reg_id = _extract_reg_id_from_doc(doc)
    if reg_id != "-":
        result["id_registrasi"] = reg_id

    if res_type == "Bundle" and isinstance(doc.get("entry"), list):
        for entry in doc["entry"]:
            if not isinstance(entry, dict):
                continue
            r = entry.get("resource")
            if not isinstance(r, dict):
                continue
            sub_info = extract_fhir_fields(r)
            for k in (
                "resource_id",
                "encounter_id",
                "patient_id",
                "patient_name",
                "id_registrasi",
            ):
                if result[k] == "-" and sub_info[k] != "-":
                    result[k] = sub_info[k]

    return result


def scrub_secrets_text(text: str) -> str:
    """Mask secret-looking fragments in a plain string."""
    text = _SECRET_TEXT_RE.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    return _BEARER_RE.sub(f"Bearer {REDACTED}", text)


def redact_sensitive_payload(obj: Any) -> Any:
    """Recursively mask credentials/tokens (dict keys and free text) while keeping structure."""
    if isinstance(obj, dict):
        return {
            k: (REDACTED if str(k).lower() in _SENSITIVE_KEYS else redact_sensitive_payload(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_sensitive_payload(item) for item in obj]
    if isinstance(obj, str):
        return scrub_secrets_text(obj)
    return obj


# ---------------------------------------------------------------------------
# PII masking
# ---------------------------------------------------------------------------

def _mask_token(tok: str, keep: int = 1) -> str:
    return (tok[:keep] + "***") if tok else tok


def mask_person_name(name: str) -> str:
    """'Budi Santoso' -> 'B*** S***'."""
    return " ".join(_mask_token(p) for p in str(name).split())


def mask_nik(value: str) -> str:
    """Keep first 4 and last 2 characters of long identifiers; fully mask short ones."""
    v = str(value)
    if len(v) < 8:
        return "***"
    return v[:4] + "*" * (len(v) - 6) + v[-2:]


def mask_tail(value: str, keep: int = 3) -> str:
    v = str(value)
    if len(v) <= keep:
        return "***"
    return "*" * max(len(v) - keep, 3) + v[-keep:]


def mask_birthdate(value: str) -> str:
    m = re.match(r"^(\d{4})", str(value))
    return f"{m.group(1)}-**-**" if m else "***"


def scrub_pii_text(text: str) -> str:
    """Secret redaction + regex scrub of NIK / e-mail / phone numbers inside free text."""
    text = scrub_secrets_text(text)
    text = _NIK_RE.sub(lambda m: mask_nik(m.group(0)), text)
    text = _EMAIL_RE.sub("***@***", text)
    return _PHONE_RE.sub(lambda m: mask_tail(m.group(0)), text)


def _ident_system_sensitive(system: Any) -> bool:
    tokens = set(re.split(r"[^a-z0-9]+", str(system or "").lower()))
    return bool(tokens & _SENSITIVE_IDENT_TOKENS)


def _mask_human_name(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in d.items():
        kl = str(k).lower()
        if kl == "text" and isinstance(v, str):
            out[k] = mask_person_name(v)
        elif kl == "family" and isinstance(v, str):
            out[k] = mask_person_name(v)
        elif kl == "given" and isinstance(v, list):
            out[k] = [mask_person_name(x) if isinstance(x, str) else x for x in v]
        else:
            out[k] = mask_pii_payload(v)
    return out


def _mask_address(a: Any) -> Any:
    if isinstance(a, list):
        return [_mask_address(i) for i in a]
    if not isinstance(a, dict):
        return mask_pii_payload(a)
    out: Dict[str, Any] = {}
    for k, v in a.items():
        kl = str(k).lower()
        if kl == "line" and isinstance(v, list):
            out[k] = ["***" for _ in v]
        elif kl == "text" and isinstance(v, str):
            out[k] = "***"
        elif kl == "postalcode" and isinstance(v, str):
            out[k] = v[:2] + "***"
        else:
            out[k] = mask_pii_payload(v)
    return out


def _mask_identifier(ident: Any) -> Any:
    if isinstance(ident, list):
        return [_mask_identifier(i) for i in ident]
    if not isinstance(ident, dict):
        return mask_pii_payload(ident)
    sensitive = _ident_system_sensitive(ident.get("system"))
    out: Dict[str, Any] = {}
    for k, v in ident.items():
        if sensitive and str(k).lower() == "value" and isinstance(v, str):
            out[k] = mask_nik(v)
        else:
            out[k] = mask_pii_payload(v)
    return out


def _mask_telecom(t: Any) -> Any:
    if isinstance(t, list):
        return [_mask_telecom(i) for i in t]
    if not isinstance(t, dict):
        return mask_pii_payload(t)
    return {
        k: (mask_tail(v) if str(k).lower() == "value" and isinstance(v, str) else mask_pii_payload(v))
        for k, v in t.items()
    }


def mask_pii_payload(obj: Any) -> Any:
    """
    Return a copy of a FHIR payload with personal data masked but structure intact, so developers
    can still verify payload *shape*. Also applies secret redaction. Free-text strings are
    regex-scrubbed for NIK / e-mail / phone, but arbitrary narrative text cannot be guaranteed clean.
    """
    if isinstance(obj, str):
        return scrub_pii_text(obj)
    if isinstance(obj, list):
        return [mask_pii_payload(i) for i in obj]
    if not isinstance(obj, dict):
        return obj

    ref = obj.get("reference")
    out: Dict[str, Any] = {}
    for k, v in obj.items():
        kl = str(k).lower()
        if kl in _SENSITIVE_KEYS:
            out[k] = REDACTED
        elif kl == "display" and isinstance(v, str) and isinstance(ref, str) and _PERSON_REF_RE.search(ref.strip()):
            out[k] = mask_person_name(v)
        elif kl == "name" and isinstance(v, list):
            out[k] = [_mask_human_name(i) if isinstance(i, dict) else mask_pii_payload(i) for i in v]
        elif kl == "name" and isinstance(v, dict):
            out[k] = _mask_human_name(v)
        elif kl == "birthdate" and isinstance(v, str):
            out[k] = mask_birthdate(v)
        elif kl == "telecom":
            out[k] = _mask_telecom(v)
        elif kl == "address":
            out[k] = _mask_address(v)
        elif kl == "identifier":
            out[k] = _mask_identifier(v)
        else:
            out[k] = mask_pii_payload(v)
    return out


def mask_url_query(url_or_path: str) -> str:
    """Mask personal search parameters (name, birthdate, NIK identifier, ...) in a path or URL."""
    base, sep, query = (url_or_path or "").partition("?")
    if not sep:
        return scrub_pii_text(base)
    parts: List[str] = []
    for k, v in parse_qsl(query, keep_blank_values=True):
        kl = k.lower()
        if kl in _QUERY_PII_KEYS:
            v = "***"
        elif kl == "identifier":
            system, bar, val = v.partition("|")
            if bar and _ident_system_sensitive(system):
                v = f"{system}|{mask_nik(val)}"
            else:
                v = scrub_pii_text(v)
        else:
            v = scrub_pii_text(v)
        parts.append(f"{quote(k, safe='')}={quote(v, safe='|:/,*')}")
    return scrub_pii_text(base) + "?" + "&".join(parts)


def cap_payload(obj: Any, max_chars: int) -> Any:
    """Replace an oversized payload with a small marker so one huge Bundle cannot fill the disk."""
    if max_chars <= 0 or obj in (None, "", {}, []):
        return obj
    try:
        size = len(obj) if isinstance(obj, str) else len(json.dumps(obj, ensure_ascii=False))
    except (TypeError, ValueError):
        return obj
    if size <= max_chars:
        return obj
    preview = (obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False))[:1000]
    return {
        "_truncated": True,
        "_size_chars": size,
        "_limit_chars": max_chars,
        "_note": "Payload exceeds max_logged_body_kb and was not stored in full.",
        "_preview": preview,
    }


def parse_body_for_log(raw_bytes: bytes, content_type: str = "") -> Tuple[Any, str]:
    """
    Parse raw HTTP body bytes into JSON object (dict/list) if valid JSON,
    otherwise return decoded text. Returns (parsed_or_text, raw_text).
    """
    if not raw_bytes:
        return {}, ""
    text = raw_bytes.decode("utf-8", errors="replace")
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
            return parsed, text
        except ValueError:  # not valid JSON: treat as plain text
            pass
    if "application/x-www-form-urlencoded" in (content_type or "").lower():
        from urllib.parse import parse_qs

        parsed_qs = {k: (v[0] if len(v) == 1 else v) for k, v in parse_qs(stripped, keep_blank_values=True).items()}
        return parsed_qs, text
    return text, text


def build_transaction_record(
    method: str,
    path: str,
    upstream_url: str,
    http_status: int,
    reason: str,
    latency_ms: int,
    req_data: Any,
    res_data: Any,
    res_raw_text: str = "",
    timestamp_dt: Optional[datetime.datetime] = None,
    mask_pii: bool = False,
    max_payload_chars: int = 0,
) -> Dict[str, Any]:
    """
    Build a canonical transaction record from an HTTP proxy exchange.

    Secrets are ALWAYS redacted. With mask_pii=True, personal data is masked as well
    (the traffic forwarded to SATUSEHAT is never modified - only what is written to the log).
    """
    now = timestamp_dt or datetime.datetime.now().astimezone()
    iso_ts = now.isoformat(timespec="seconds")
    waktu_kirim = now.strftime("%d/%m/%y %H:%M:%S")

    path_res_name, path_res_id = detect_resource_from_path(path)
    is_success = 200 <= http_status < 300
    status_label = "Sukses" if is_success else "Gagal"
    resp_label = http_status_label(http_status, reason)

    req_data = redact_sensitive_payload(req_data)
    res_data = redact_sensitive_payload(res_data)

    res_fields = extract_fhir_fields(res_data, fallback_resource=path_res_name)
    req_fields = extract_fhir_fields(req_data, fallback_resource=path_res_name)

    resource_name = res_fields["resource_name"]
    if resource_name in ("", "FHIR", "OperationOutcome") and req_fields["resource_name"] not in ("", "FHIR"):
        resource_name = req_fields["resource_name"]
    if resource_name in ("", "FHIR", "OperationOutcome"):
        resource_name = path_res_name

    merged: Dict[str, str] = {}
    for key in ("resource_id", "encounter_id", "patient_id", "patient_name", "id_registrasi"):
        val = res_fields.get(key, "-")
        if val == "-":
            val = req_fields.get(key, "-")
        merged[key] = val

    if merged["resource_id"] == "-" and path_res_id != "-":
        merged["resource_id"] = path_res_id

    if is_success:
        rule_number, error_summary = "-", ""
    else:
        rule_number, error_summary = extract_rule_and_error(
            res_data, http_status=http_status, raw_text=res_raw_text
        )

    error_summary = scrub_secrets_text(error_summary)
    log_path = path
    log_url = upstream_url
    if mask_pii:
        merged["patient_name"] = (
            mask_person_name(merged["patient_name"]) if merged["patient_name"] != "-" else "-"
        )
        error_summary = scrub_pii_text(error_summary)
        log_path = mask_url_query(path)
        log_url = mask_url_query(upstream_url)
        req_data = mask_pii_payload(req_data)
        res_data = mask_pii_payload(res_data)

    req_data = cap_payload(req_data, max_payload_chars)
    res_data = cap_payload(res_data, max_payload_chars)

    uid_seed = f"{iso_ts}_{method}_{log_path}_{http_status}_{latency_ms}_{merged['resource_id']}"
    uid = hashlib.sha256(uid_seed.encode("utf-8")).hexdigest()[:16]

    return {
        "id": f"px_{uid}_{int(now.timestamp() * 1000) % 100000}",
        "timestamp": iso_ts,
        "waktu_kirim": waktu_kirim,
        "resource_name": resource_name,
        "method": method.upper(),
        "status": status_label,
        "http_status": http_status,
        "response": resp_label,
        "rule_number": rule_number,
        "resource_id": merged["resource_id"],
        "encounter_id": merged["encounter_id"],
        "patient_id": merged["patient_id"],
        "patient_name": merged["patient_name"],
        "id_registrasi": merged["id_registrasi"],
        "latency_ms": int(latency_ms),
        "url": log_url,
        "path": log_path,
        "pii_masked": bool(mask_pii),
        "error_summary": error_summary,
        "request_payload": req_data if req_data not in (None, "") else {},
        "response_payload": res_data if res_data not in (None, "") else {},
    }
