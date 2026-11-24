import copy
import hashlib
import json
import unittest
from pathlib import Path

from kubit.feed import (
    FeedValidationError,
    canonical_json,
    compute_feed_revision,
    finalize_feed,
    validate_feed,
)


SCHEMA = Path(__file__).parents[1] / "schemas" / "compatibility-evidence-feed-v1.schema.json"


def candidate_feed():
    return {
        "schema_version": 1,
        "generated_at": "2026-11-24T10:00:00Z",
        "expires_at": "2026-12-01T10:00:00Z",
        "providers": [
            {
                "name": "z-provider",
                "parser_version": "2",
                "retrieved_at": "2026-11-24T09:59:00Z",
                "source": {
                    "requested_url": "https://example.test/main/support.md",
                    "resolved_url": "https://example.test/commits/abc/support.md",
                    "revision": "abc",
                    "media_type": "text/markdown",
                    "sha256": "a" * 64,
                },
                "rules": [
                    {"id": "z-rule", "type": "matrix", "evidence": "https://example.test/support"},
                    {"id": "a-rule", "type": "matrix", "evidence": "https://example.test/support"},
                ],
            },
            {
                "name": "a-provider",
                "parser_version": "1",
                "retrieved_at": "2026-11-24T09:58:00Z",
                "source": {
                    "requested_url": "https://upstream.test/releases.json",
                    "resolved_url": "https://upstream.test/releases/1.json",
                    "media_type": "application/json",
                    "sha256": "b" * 64,
                },
                "rules": [
                    {"id": "middle-rule", "type": "version_skew", "evidence": "https://upstream.test/policy"}
                ],
            },
        ],
    }


class FeedContractTest(unittest.TestCase):
    def test_schema_is_valid_json_and_declares_v1(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertFalse(schema["additionalProperties"])

    def test_finalize_normalizes_and_assigns_stable_revision(self):
        first = finalize_feed(candidate_feed())
        reordered = candidate_feed()
        reordered["providers"].reverse()
        for provider in reordered["providers"]:
            provider["rules"].reverse()
        second = finalize_feed(reordered)

        self.assertEqual(first, second)
        self.assertEqual([provider["name"] for provider in first["providers"]], ["a-provider", "z-provider"])
        self.assertEqual([rule["id"] for rule in first["providers"][1]["rules"]], ["a-rule", "z-rule"])
        self.assertEqual(first["feed_revision"], compute_feed_revision(first))
        self.assertEqual(
            first["feed_revision"],
            "sha256:1e77c5c6188b1bd0e0600ea8d5f557793bac6337bdd6c58ba22ef209248640d8",
        )

    def test_canonical_json_is_compact_utf8_and_rejects_floats(self):
        encoded = canonical_json({"z": "Kubernetes", "a": "Säker"})
        self.assertEqual(encoded, '{"a":"Säker","z":"Kubernetes"}'.encode())
        with self.assertRaisesRegex(FeedValidationError, "unsupported JSON value float"):
            canonical_json({"value": 1.5})

    def test_digest_detects_content_corruption(self):
        feed = finalize_feed(candidate_feed())
        corrupted = copy.deepcopy(feed)
        corrupted["providers"][0]["source"]["sha256"] = "c" * 64
        with self.assertRaisesRegex(FeedValidationError, "feed_revision mismatch"):
            validate_feed(corrupted)

    def test_rejects_duplicate_rules_and_unofficial_urls(self):
        duplicate = candidate_feed()
        duplicate["providers"][1]["rules"][0]["id"] = "a-rule"
        with self.assertRaisesRegex(FeedValidationError, "duplicate rule id"):
            finalize_feed(duplicate)

        unofficial = candidate_feed()
        unofficial["providers"][0]["rules"][0]["evidence"] = "http://example.test/support"
        with self.assertRaisesRegex(FeedValidationError, "must use HTTPS"):
            finalize_feed(unofficial)

    def test_rejects_invalid_lifecycle_and_unknown_fields(self):
        expired = candidate_feed()
        expired["expires_at"] = expired["generated_at"]
        with self.assertRaisesRegex(FeedValidationError, "later than generated_at"):
            finalize_feed(expired)

        unexpected = candidate_feed()
        unexpected["channel"] = "stable"
        with self.assertRaisesRegex(FeedValidationError, "unexpected fields: channel"):
            finalize_feed(unexpected)

    def test_revision_is_sha256_of_canonical_payload_without_revision(self):
        feed = finalize_feed(candidate_feed())
        payload = copy.deepcopy(feed)
        payload.pop("feed_revision")
        expected = hashlib.sha256(canonical_json(payload)).hexdigest()
        self.assertEqual(feed["feed_revision"], f"sha256:{expected}")


if __name__ == "__main__":
    unittest.main()
