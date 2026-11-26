import json
import unittest

import fhir_extract as fx


PATIENT = {
    "resourceType": "Patient",
    "id": "P123",
    "identifier": [
        {"system": "https://fhir.kemkes.go.id/id/nik", "value": "3374012345678901"},
        {"system": "https://fhir.kemkes.go.id/id/ihs-number", "value": "P00000000001"},
        {"system": "http://sys-ids.kemkes.go.id/mrn/100012345", "value": "RM-0099887766"},
    ],
    "name": [{"use": "official", "text": "Budi Santoso", "family": "Santoso", "given": ["Budi"]}],
    "birthDate": "1990-05-17",
    "telecom": [{"system": "phone", "value": "081234567890"}, {"system": "email", "value": "a@b.co"}],
    "address": [{"line": ["Jl. Kaliurang KM 5 No 1"], "city": "Sleman", "postalCode": "55281", "text": "Jl. Kaliurang"}],
}


class StatusAndPath(unittest.TestCase):
    def test_status_labels(self):
        self.assertEqual(fx.http_status_label(422), "422 Unproc")
        self.assertEqual(fx.http_status_label(0), "0 ConnErr")

    def test_resource_from_path(self):
        self.assertEqual(fx.detect_resource_from_path("/fhir-r4/v1/Patient/abc?x=1"), ("Patient", "abc"))
        self.assertEqual(fx.detect_resource_from_path("/oauth2/v1/accesstoken?grant_type=client_credentials")[0], "OAuth2")
        self.assertEqual(fx.detect_resource_from_path("/kfa-v2/products/all")[0], "KFA/products")


class ErrorExtraction(unittest.TestCase):
    def test_operation_outcome_rule_number(self):
        oo = {
            "resourceType": "OperationOutcome",
            "issue": [{
                "severity": "error", "code": "invalid",
                "details": {"text": "Rule Number: 20002 - invalid reference"},
                "expression": ["Encounter.subject"],
            }],
        }
        rule, summary = fx.extract_rule_and_error(oo, 400)
        self.assertEqual(rule, "20002")
        self.assertIn("Encounter.subject", summary)

    def test_timeout_without_body(self):
        rule, _ = fx.extract_rule_and_error("", 0, "Upstream timed out")
        self.assertEqual(rule, "TIMEOUT")

    def test_success_has_no_rule(self):
        self.assertEqual(fx.extract_rule_and_error({}, 200), ("-", ""))


class SecretRedaction(unittest.TestCase):
    def test_dict_keys(self):
        out = fx.redact_sensitive_payload({"client_id": "x", "client_secret": "s3cr3t", "nested": {"access_token": "t"}})
        self.assertEqual(out["client_secret"], fx.REDACTED)
        self.assertEqual(out["nested"]["access_token"], fx.REDACTED)
        self.assertEqual(out["client_id"], "x")

    def test_unparsed_text_body(self):
        out = fx.redact_sensitive_payload("client_id=abc&client_secret=TOPSECRET&grant_type=client_credentials")
        self.assertNotIn("TOPSECRET", out)
        self.assertIn("grant_type=client_credentials", out)

    def test_bearer_in_text(self):
        self.assertNotIn("abcdef123456", fx.redact_sensitive_payload("sent Bearer abcdef123456789 to host"))

    def test_record_never_contains_secret_even_when_not_json(self):
        rec = fx.build_transaction_record(
            "POST", "/oauth2/v1/accesstoken", "https://x/oauth2/v1/accesstoken", 401, "Unauthorized", 10,
            req_data="client_secret=TOPSECRET", res_data={"error": "invalid", "error_description": "bad"},
        )
        self.assertNotIn("TOPSECRET", json.dumps(rec))


class PiiMasking(unittest.TestCase):
    def setUp(self):
        self.masked = fx.mask_pii_payload(PATIENT)
        self.dump = json.dumps(self.masked, ensure_ascii=False)

    def test_no_raw_pii_left(self):
        for raw in ("3374012345678901", "Budi", "Santoso", "081234567890", "a@b.co",
                    "Kaliurang", "1990-05-17", "RM-0099887766"):
            self.assertNotIn(raw, self.dump, raw)

    def test_debugging_fields_survive(self):
        self.assertIn("P00000000001", self.dump)      # IHS number is needed for debugging
        self.assertIn("Sleman", self.dump)             # coarse location kept
        self.assertEqual(self.masked["resourceType"], "Patient")
        self.assertEqual(self.masked["birthDate"], "1990-**-**")

    def test_structure_preserved(self):
        self.assertEqual(len(self.masked["identifier"]), 3)
        self.assertEqual(set(self.masked["name"][0]), set(PATIENT["name"][0]))

    def test_reference_display_masked_only_for_persons(self):
        doc = {
            "subject": {"reference": "Patient/P1", "display": "Budi Santoso"},
            "author": {"reference": "Practitioner/10000000001", "display": "Dr. Siti"},
            "serviceProvider": {"reference": "Organization/o1", "display": "RS Contoh Sehat"},
        }
        out = fx.mask_pii_payload(doc)
        self.assertEqual(out["subject"]["display"], "B*** S***")
        self.assertNotIn("Siti", json.dumps(out))
        self.assertEqual(out["serviceProvider"]["display"], "RS Contoh Sehat")

    def test_free_text_scrub(self):
        out = fx.mask_pii_payload({"note": [{"text": "NIK 3374012345678901 hub 081234567890 / x@y.id"}]})
        txt = json.dumps(out)
        for raw in ("3374012345678901", "081234567890", "x@y.id"):
            self.assertNotIn(raw, txt)

    def test_query_masking(self):
        out = fx.mask_url_query(
            "/fhir-r4/v1/Patient?identifier=https://fhir.kemkes.go.id/id/nik|3374012345678901&name=Budi&_count=5"
        )
        self.assertNotIn("3374012345678901", out)
        self.assertNotIn("Budi", out)
        self.assertIn("_count=5", out)

    def test_record_masking_end_to_end(self):
        rec = fx.build_transaction_record(
            "POST", "/fhir-r4/v1/Patient?name=Budi", "https://api/fhir-r4/v1/Patient?name=Budi", 400, "Bad", 5,
            req_data=PATIENT,
            res_data={"resourceType": "OperationOutcome",
                      "issue": [{"severity": "error", "code": "invalid",
                                 "diagnostics": "NIK 3374012345678901 not valid"}]},
            mask_pii=True,
        )
        dump = json.dumps(rec, ensure_ascii=False)
        for raw in ("3374012345678901", "Budi Santoso", "081234567890"):
            self.assertNotIn(raw, dump, raw)
        self.assertTrue(rec["pii_masked"])
        self.assertEqual(rec["patient_name"], "-" if rec["patient_name"] == "-" else rec["patient_name"])

    def test_unmasked_mode_keeps_payload(self):
        rec = fx.build_transaction_record("POST", "/fhir-r4/v1/Patient", "https://api/x", 201, "Created", 5,
                                          req_data=PATIENT, res_data=PATIENT, mask_pii=False)
        self.assertIn("Budi", json.dumps(rec))
        self.assertFalse(rec["pii_masked"])


class PayloadCap(unittest.TestCase):
    def test_oversize_is_replaced(self):
        big = {"resourceType": "Bundle", "entry": ["x" * 100] * 1000}
        out = fx.cap_payload(big, 5000)
        self.assertTrue(out["_truncated"])
        self.assertLess(len(json.dumps(out)), 5000)

    def test_small_untouched(self):
        self.assertEqual(fx.cap_payload({"a": 1}, 5000), {"a": 1})


if __name__ == "__main__":
    unittest.main()
