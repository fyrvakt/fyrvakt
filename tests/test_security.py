import json
import unittest
from datetime import datetime, timezone

from kubit.models import Component
from kubit.security import (
    MAX_FINDINGS_PER_REPORT,
    MIN_HIGH_FINDINGS_PER_REPORT,
    MAX_SBOM_COMPONENTS_PER_REPORT,
    REPORT_PATHS,
    SecurityCollector,
    sbom_package_page,
)


class FakeAPI:
    def __init__(self, documents=None):
        self.documents = documents or {}

    def get(self, path):
        if path not in self.documents:
            raise RuntimeError(f"Kubernetes API {path} returned HTTP 404")
        return self.documents[path]

    def list_page(self, path, limit, continue_token=""):
        return self.get(path)


class TransientAPI(FakeAPI):
    def __init__(self, documents, throttled_path):
        super().__init__(documents)
        self.throttled_path = throttled_path
        self.calls = 0

    def get(self, path):
        if path == self.throttled_path:
            self.calls += 1
            if self.calls == 1:
                error = RuntimeError("temporarily throttled")
                error.status = 429
                error.retry_after = 0
                raise error
        return super().get(path)


class PaginatedAPI(FakeAPI):
    def __init__(self, pages):
        super().__init__()
        self.pages = pages
        self.requests = []

    def list_page(self, path, limit, continue_token=""):
        self.requests.append((path, limit, continue_token))
        return self.pages.get((path, continue_token), {"items": []})


def report_item(kind, name, report, container="app"):
    return {
        "metadata": {
            "name": f"{name}-{container or 'workload'}",
            "namespace": "demo",
            "creationTimestamp": datetime.now(timezone.utc).isoformat(),
            "labels": {
                "trivy-operator.resource.namespace": "demo",
                "trivy-operator.resource.kind": kind,
                "trivy-operator.resource.name": name,
                "trivy-operator.container.name": container,
            },
        },
        "report": report,
    }


class SecurityCollectorTest(unittest.TestCase):
    def test_collects_correlates_and_sanitizes_trivy_reports(self):
        timestamp = datetime.now(timezone.utc).isoformat()
        scanner = {"name": "Trivy", "vendor": "Aqua Security", "version": "0.76.1"}
        artifact = {"repository": "example/demo", "tag": "1.2.3", "digest": "sha256:abc"}
        vulnerability = report_item(
            "Deployment",
            "demo",
            {
                "artifact": artifact,
                "registry": {"server": "registry.example"},
                "scanner": scanner,
                "updateTimestamp": timestamp,
                "summary": {"criticalCount": 1, "highCount": 2},
                "vulnerabilities": [
                    {
                        "vulnerabilityID": "CVE-2026-0001",
                        "severity": "CRITICAL",
                        "resource": "libdemo",
                        "installedVersion": "1.0",
                        "fixedVersion": "1.1",
                        "title": "Example vulnerability",
                        "primaryLink": "https://security.example/CVE-2026-0001",
                    },
                    {
                        "vulnerabilityID": "UNSAFE",
                        "severity": "HIGH",
                        "primaryLink": "javascript:alert(1)",
                    },
                ],
            },
        )
        secret = report_item(
            "Deployment",
            "demo",
            {
                "artifact": artifact,
                "scanner": scanner,
                "updateTimestamp": timestamp,
                "summary": {"criticalCount": 1},
                "secrets": [{"ruleID": "secret-key", "match": "do-not-expose-this-value"}],
            },
        )
        config = report_item(
            "Deployment",
            "demo",
            {
                "scanner": scanner,
                "updateTimestamp": timestamp,
                "summary": {"mediumCount": 1},
                "checks": [{"checkID": "KSV001", "severity": "MEDIUM", "title": "Run as non-root", "success": False, "messages": ["untrusted detail"]}],
            },
            container="",
        )
        sbom = report_item(
            "Deployment",
            "demo",
            {"artifact": artifact, "scanner": scanner, "updateTimestamp": timestamp, "summary": {"componentsCount": 12}},
        )
        api = FakeAPI(
            {
                REPORT_PATHS["vulnerability"]: {"items": [vulnerability]},
                REPORT_PATHS["config_audit"]: {"items": [config]},
                REPORT_PATHS["exposed_secret"]: {"items": [secret]},
                REPORT_PATHS["sbom"]: {"items": [sbom]},
            }
        )
        components = [
            Component(
                "demo",
                "1.2.3",
                "deployment/demo/demo",
                "demo",
                {"namespace": "demo", "workload_kind": "deployment", "workload_name": "demo", "container": "app", "image": "registry.example/example/demo:1.2.3"},
            )
        ]

        result = SecurityCollector(api, stale_after_seconds=3600).collect(components)

        self.assertTrue(result["available"])
        self.assertEqual(result["status"], "fresh")
        self.assertEqual(result["summary"]["critical"], 1)
        self.assertEqual(result["summary"]["high"], 2)
        self.assertEqual(result["summary"]["fixable"], 1)
        self.assertEqual(result["summary"]["exposed_secrets"], 1)
        self.assertEqual(result["summary"]["sbom_components"], 12)
        self.assertEqual(result["summary"]["covered_containers"], 1)
        vuln_report = next(item for item in result["reports"] if item["report_type"] == "vulnerability")
        self.assertEqual(vuln_report["component"], "demo")
        self.assertEqual(vuln_report["inventory"]["workload_name"], "demo")
        self.assertEqual(vuln_report["image"], "registry.example/example/demo:1.2.3")
        self.assertEqual(vuln_report["findings"][1]["url"], "")
        self.assertFalse(vuln_report["findings_truncated"])
        sbom_report = next(item for item in result["reports"] if item["report_type"] == "sbom")
        self.assertEqual(sbom_report["sbom_packages"], [])
        self.assertTrue(sbom_report["sbom_packages_truncated"])
        serialized = json.dumps(result)
        self.assertNotIn("do-not-expose-this-value", serialized)
        self.assertNotIn("untrusted detail", serialized)

    def test_bounded_vulnerability_details_reserve_space_for_high_findings(self):
        timestamp = datetime.now(timezone.utc).isoformat()
        vulnerabilities = [
            {"vulnerabilityID": f"CVE-CRITICAL-{index:03d}", "severity": "CRITICAL"}
            for index in range(MAX_FINDINGS_PER_REPORT + 10)
        ] + [
            {"vulnerabilityID": f"CVE-HIGH-{index:03d}", "severity": "HIGH"}
            for index in range(MAX_FINDINGS_PER_REPORT + 10)
        ]
        vulnerability = report_item(
            "Deployment",
            "demo",
            {
                "updateTimestamp": timestamp,
                "summary": {
                    "criticalCount": MAX_FINDINGS_PER_REPORT + 10,
                    "highCount": MAX_FINDINGS_PER_REPORT + 10,
                },
                "vulnerabilities": vulnerabilities,
            },
        )
        documents = {path: {"items": []} for path in REPORT_PATHS.values()}
        documents[REPORT_PATHS["vulnerability"]] = {"items": [vulnerability]}

        result = SecurityCollector(FakeAPI(documents), stale_after_seconds=3600).collect([])

        report = result["reports"][0]
        severities = [finding["severity"] for finding in report["findings"]]
        self.assertEqual(len(severities), MAX_FINDINGS_PER_REPORT)
        self.assertEqual(severities.count("high"), MIN_HIGH_FINDINGS_PER_REPORT)
        self.assertEqual(
            severities.count("critical"),
            MAX_FINDINGS_PER_REPORT - MIN_HIGH_FINDINGS_PER_REPORT,
        )
        self.assertTrue(report["findings_truncated"])

    def test_sbom_package_details_are_bounded_and_sanitized(self):
        timestamp = datetime.now(timezone.utc).isoformat()
        packages = [
            {
                "name": f"package-{index:02d}",
                "version": f"1.0.{index}",
                "type": "library",
                "group": "example",
                "purl": f"pkg:generic/package-{index:02d}@1.0.{index}",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "hashes": [{"alg": "SHA-256", "content": "do-not-export-hash"}],
                "supplier": {"contact": [{"email": "do-not-export@example.test"}]},
            }
            for index in range(MAX_SBOM_COMPONENTS_PER_REPORT + 5)
        ]
        sbom = report_item(
            "Deployment",
            "demo",
            {
                "updateTimestamp": timestamp,
                "summary": {"componentsCount": len(packages), "dependenciesCount": 0},
                "components": {"bomFormat": "CycloneDX", "components": packages},
            },
        )
        documents = {path: {"items": []} for path in REPORT_PATHS.values()}
        documents[REPORT_PATHS["sbom"]] = {"items": [sbom]}

        result = SecurityCollector(FakeAPI(documents), stale_after_seconds=3600).collect([])

        report = result["reports"][0]
        self.assertEqual(len(report["sbom_packages"]), MAX_SBOM_COMPONENTS_PER_REPORT)
        self.assertTrue(report["sbom_packages_truncated"])
        self.assertEqual(report["sbom_packages"][0]["name"], "package-00")
        self.assertEqual(report["sbom_packages"][0]["licenses"], ["Apache-2.0"])
        serialized = json.dumps(result)
        self.assertNotIn("do-not-export-hash", serialized)
        self.assertNotIn("do-not-export@example.test", serialized)

    def test_collects_all_paginated_report_pages(self):
        timestamp = datetime.now(timezone.utc).isoformat()
        first = report_item(
            "Deployment",
            "first",
            {"updateTimestamp": timestamp, "summary": {"criticalCount": 1}},
        )
        second = report_item(
            "Deployment",
            "second",
            {"updateTimestamp": timestamp, "summary": {"highCount": 1}},
        )
        pages = {
            (REPORT_PATHS["vulnerability"], ""): {
                "items": [first],
                "metadata": {"continue": "next-page"},
            },
            (REPORT_PATHS["vulnerability"], "next-page"): {"items": [second]},
        }
        api = PaginatedAPI(pages)

        result = SecurityCollector(
            api,
            stale_after_seconds=3600,
            retry_delay_seconds=0,
            page_size=25,
        ).collect([])

        self.assertEqual(result["summary"]["reports"], 2)
        self.assertEqual(result["summary"]["critical"], 1)
        self.assertEqual(result["summary"]["high"], 1)
        self.assertEqual(
            api.requests[:2],
            [
                (REPORT_PATHS["vulnerability"], 25, ""),
                (REPORT_PATHS["vulnerability"], 25, "next-page"),
            ],
        )

    def test_discards_partial_report_type_when_pagination_token_repeats(self):
        timestamp = datetime.now(timezone.utc).isoformat()
        item = report_item(
            "Deployment",
            "partial",
            {"updateTimestamp": timestamp, "summary": {"criticalCount": 1}},
        )
        pages = {
            (REPORT_PATHS["vulnerability"], ""): {
                "items": [item],
                "metadata": {"continue": "repeated"},
            },
            (REPORT_PATHS["vulnerability"], "repeated"): {
                "items": [],
                "metadata": {"continue": "repeated"},
            },
        }

        result = SecurityCollector(
            PaginatedAPI(pages),
            stale_after_seconds=3600,
            retry_delay_seconds=0,
        ).collect([])

        self.assertEqual(result["summary"]["reports"], 0)
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(any("repeated a pagination token" in error for error in result["errors"]))

    def test_sbom_package_endpoint_pages_and_searches_all_sanitized_packages(self):
        packages = [
            {
                "name": f"package-{index:03d}",
                "version": "2.0" if index == 76 else "1.0",
                "type": "library",
                "purl": f"pkg:generic/package-{index:03d}",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "hashes": [{"content": "do-not-return"}],
            }
            for index in range(120)
        ]
        path = "/apis/aquasecurity.github.io/v1alpha1/namespaces/demo/sbomreports/demo-app"
        api = FakeAPI({path: {"report": {"components": {"components": packages}}}})

        page = sbom_package_page(api, "demo", "demo-app", offset=50, limit=25)
        searched = sbom_package_page(api, "demo", "demo-app", query="package-076")

        self.assertEqual(page["total"], 120)
        self.assertEqual(page["packages"][0]["name"], "package-050")
        self.assertEqual(page["next_offset"], 75)
        self.assertEqual(searched["matched"], 1)
        self.assertEqual(searched["packages"][0]["version"], "2.0")
        self.assertNotIn("do-not-return", json.dumps(page))

    def test_unavailable_crds_are_unknown_not_clean(self):
        result = SecurityCollector(FakeAPI(), stale_after_seconds=3600).collect([])
        self.assertFalse(result["available"])
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["summary"]["vulnerabilities"], 0)
        self.assertEqual(len(result["errors"]), 4)

    def test_retries_transient_api_throttling(self):
        documents = {path: {"items": []} for path in REPORT_PATHS.values()}
        api = TransientAPI(documents, REPORT_PATHS["config_audit"])
        result = SecurityCollector(api, stale_after_seconds=3600, retry_delay_seconds=0).collect([])
        self.assertEqual(api.calls, 2)
        self.assertTrue(result["available"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
