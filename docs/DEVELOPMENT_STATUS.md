# Kubit development status

Last updated: 2026-11-24

This document is the handoff point for Kubit application development. The
public GitHub repository is the single source of truth for source, tests,
container builds, reusable manifests, the Helm chart, releases, and development
continuity. Private environment deployment state belongs in the corresponding
deployment repository.

## Current objective

Implement the versioned compatibility evidence feed described in
[`docs/evidence-feed.md`](evidence-feed.md). Official upstream documents remain
the authority, while Kubit stores their exact bytes and normalized rules as
immutable, content-addressed revisions. Compatibility evaluation must always
consume a validated local revision so a mutable page, markup change, or
temporary upstream outage cannot break a cluster scan.

The first implementation increment defines the version 1 JSON Schema,
deterministic canonical encoding, revision digest, and structural and semantic
validation without changing runtime provider behavior. The next increment is
to retain immutable raw documents and multiple local generations, then build
candidate revisions from that history. Runtime cutover comes later through a
`FeedReader`, shadow comparison, and controlled promotion; the existing
direct-provider path remains the rollback until equivalence is proven.

Kubernetes is the central compatibility axis. Kubit first validates observable
control-plane, node, runtime, and networking components, then evaluates every
detected platform application against the observed or proposed Kubernetes
version. Missing, unverifiable, or stale evidence remains `unknown` or `stale`;
it never becomes an inferred supported result.

## Repository ownership

| Repository | Responsibility |
| --- | --- |
| this repository | Application source, tests, Dockerfile, GHCR image, Helm chart, generic Kustomize resources, and releases |
| private deployment repositories | Environment-specific values, release pins, secrets integration, ingress, storage, and monitoring labels |
| Argo CD repository | Parent Applications and cluster reconciliation |

The former ESS image-publishing repository is not part of the release path for
new versions. Release tags in this repository build multi-architecture images,
publish immutable semantic-version tags to GHCR, package the chart, and create
the GitHub Release.

## Current release

The current source and release version is `1.5.1`.

Release `1.5.1` includes:

- bounded Kubernetes list pagination for all four Trivy report collections;
- bounded, searchable, on-demand browsing of complete SBOM package lists;
- a full-width SBOM detail layout in the Security view;
- safe chart defaults of 50 report objects per Kubernetes page and one
  concurrent SBOM lookup, including upgrades that reuse older values;
- the existing automatic inventory, evidence providers, upgrade simulation,
  authentication, source proposals, Prometheus/Grafana integration, and
  optional CloudNativePG persistence.

Release `1.5.0` was superseded without deployment after an upgrade dry run
found that newly introduced numeric values could render as zero when old Helm
values were reused. The corrected chart templates in `1.5.1` preserve bounded
defaults.

## Validation baseline

The `1.5.1` release passed:

- 83 Python unit and regression tests;
- release-version consistency checks;
- Grafana dashboard JSON validation;
- generic, monitoring, and PostgreSQL Kustomize renders;
- Helm lint and template checks for default, observability, and CloudNativePG
  configurations;
- a production container build and installed-package version check;
- the release workflow that publishes the image and packaged chart.

Local development checks:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/set_version.py --check
python3 -m json.tool components/monitoring/dashboard.json >/dev/null
kubectl kustomize base >/dev/null
helm lint charts/kubit
helm template kubit charts/kubit --namespace kubit >/dev/null
docker build -t kubit:dev .
git diff --check
```

## Current risks

- Promotion granularity, retention, and trust policy still require explicit
  decisions. Do not cut the runtime over before schema validation, local
  last-known-good behavior, and shadow-mode equivalence are tested.
- A packaged bootstrap feed cannot remain green indefinitely. Expired local or
  bootstrap evidence must expose `stale` and stop creating new supported claims
  even when it is the only available revision.
- Direct Kubernetes compatibility coverage is still missing for Cilium and
  Kasten. Components without verified official evidence must remain unknown.
- Elasticsearch compatibility must not be inferred unless ECK ownership and an
  applicable official relationship are established.
- An on-demand SBOM request still decodes one selected Kubernetes object because
  arrays nested inside a custom resource cannot be paginated by the Kubernetes
  API. Concurrency and response data remain bounded, but transient memory should
  be measured with unusually large reports.
- The optional PostgreSQL component requires an explicit HA, backup, restore,
  and upgrade design before production use.
- Source proposals remain non-operational candidates until administrator
  decisions and a source-specific parser gate are implemented. A stored URL
  alone can never create a compatibility result.

## Decisions

| Date | Decision | Reason |
| --- | --- | --- |
| 2026-11-24 | Define feed schema v1 with integer-only canonical JSON and a digest over the normalized envelope excluding `feed_revision`. | Keep revision generation deterministic across languages and avoid a self-referential digest while leaving publication policy independent. |
| 2026-11-24 | Make a validated immutable local feed revision the runtime source of truth. | Cluster scans must remain reproducible and available when upstream pages change layout or become unavailable, while every rule retains official provenance and freshness. |
| 2026-11-24 | Make this GitHub repository the single application-development source. | Keep code, tests, generic packaging, releases, and development continuity together while private repositories only consume releases. |
| 2026-11-24 | Keep private operational state out of this public status document. | Cluster names, Vault details, runtime findings, and environment configuration belong to private deployment repositories. |
| 2026-11-18 | Supersede `1.5.0` with `1.5.1` without deploying `1.5.0`. | Reused Helm values exposed unsafe zero-valued defaults; the patch release preserves explicit bounds. |
| 2026-11-17 | Page Trivy lists and browse complete SBOM packages on demand. | Keep scan history and the main report bounded while allowing package-level inspection. |
| 2026-10-27 | Treat Kubernetes as the central compatibility axis and unknown evidence as non-green. | Compatibility claims must be evidence-backed and must not be inferred from absence. |

## Next concrete step

Complete the design/contracts increment, then add immutable local history:
store raw source bytes by SHA-256, retain multiple generations, validate stored
source digests, and preserve current runtime behavior. After that, build
candidate revisions with semantic-regression tests and introduce the
`FeedReader` boundary and shadow comparison before any controlled runtime
cutover. Administrator proposal decisions and new Cilium or Kasten providers
remain follow-up work after this foundation.
