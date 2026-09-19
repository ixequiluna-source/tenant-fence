import copy
import tempfile
import unittest
from pathlib import Path

from tenant_fence.core import InvalidExperiment, evaluate, request, validate
from tenant_fence.demo import SPEC, TOKENS, fixture
from tenant_fence.report import write_report


class TenantTests(unittest.TestCase):
    def test_secure_matrix(self):
        with fixture("secure") as base:
            result = evaluate(base, SPEC, TOKENS)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(len(result["checks"]), 12)

    def test_object_level_bypass(self):
        self.assert_mode("broken-object", "FAIL")

    def test_trusted_client_header(self):
        self.assert_mode("header-trust", "FAIL")

    def test_collection_disclosure(self):
        self.assert_mode("leaky-list", "FAIL")

    def test_denial_body_leak(self):
        self.assert_mode("leaky-error", "FAIL")

    def test_cache_not_partitioned_by_identity(self):
        self.assert_mode("leaky-cache", "FAIL")

    def test_blanket_denial_is_not_security_proof(self):
        self.assert_mode("denied", "INCONCLUSIVE")

    def test_service_outage_is_not_pass(self):
        self.assert_mode("unavailable", "INCONCLUSIVE")

    def test_redirect_is_not_followed(self):
        self.assert_mode("redirect", "INCONCLUSIVE")

    def assert_mode(self, mode, verdict):
        with fixture(mode) as base:
            self.assertEqual(evaluate(base, SPEC, TOKENS)["verdict"], verdict)

    def test_missing_token_is_invalid(self):
        with self.assertRaises(InvalidExperiment):
            validate("http://127.0.0.1:8000", SPEC, {})

    def test_same_token_is_invalid(self):
        env = dict.fromkeys(TOKENS, "same-synthetic-token")
        with self.assertRaises(InvalidExperiment):
            validate("http://127.0.0.1:8000", SPEC, env)

    def test_public_or_ambiguous_targets_rejected_before_network(self):
        for target in [
            "https://example.com",
            "http://192.168.1.1:80",
            "http://localhost:80",
            "http://127.0.0.1",
            "http://127.0.0.1:80/path",
            "http://user@127.0.0.1:80",
            "http://127.0.0.1:80?x=1",
            "ftp://127.0.0.1:80",
            "http://127.0.0.1:99999",
        ]:
            with self.subTest(target=target), self.assertRaises(InvalidExperiment):
                validate(target, SPEC, TOKENS)

    def test_ambiguous_manifest_rejected(self):
        for value in [None, {}, [], {"tenants": []}]:
            with self.subTest(value=value), self.assertRaises(InvalidExperiment):
                validate("http://127.0.0.1:80", value, TOKENS)

    def test_route_escape_rejected(self):
        for route in [
            "//example.com/{id}",
            "/../{id}",
            "/records/{id}}",
            "/records/{unknown}",
            "/records/{id}?x=1",
        ]:
            spec = copy.deepcopy(SPEC)
            spec["detail"] = route
            with self.subTest(route=route), self.assertRaises(InvalidExperiment):
                validate("http://127.0.0.1:80", spec, TOKENS)

    def test_duplicate_identity_rejected(self):
        spec = copy.deepcopy(SPEC)
        spec["tenants"][1]["id"] = "alpha"
        with self.assertRaises(InvalidExperiment):
            validate("http://127.0.0.1:80", spec, TOKENS)

    def test_missing_record_breaks_positive_control(self):
        spec = copy.deepcopy(SPEC)
        spec["tenants"][0]["resource"] = "absent"
        with fixture("secure") as base:
            self.assertEqual(evaluate(base, spec, TOKENS)["verdict"], "INCONCLUSIVE")

    def test_no_tokens_or_payloads_in_report(self):
        with fixture("broken-object") as base:
            result = evaluate(base, SPEC, TOKENS)
        with tempfile.TemporaryDirectory() as directory:
            write_report(directory, "tenant-fence", "Boundary checks", [result])
            for p in Path(directory).iterdir():
                content = p.read_text()
                for token in TOKENS.values():
                    self.assertNotIn(token, content)
                for tenant in SPEC["tenants"]:
                    self.assertNotIn(tenant["marker"], content)

    def test_unreachable_target_is_not_pass(self):
        with fixture() as base:
            pass
        status, body = request(base, "/records", timeout=0.1)
        self.assertIsNone(status)
        self.assertIsNone(body)

    def test_manifest_not_mutated(self):
        old = copy.deepcopy(SPEC)
        with fixture() as base:
            evaluate(base, SPEC, TOKENS)
        self.assertEqual(old, SPEC)


if __name__ == "__main__":
    unittest.main()
