# Compatibility evidence feed

Status: proposed. Track the design decision and implementation in
[GitHub issue #7](https://github.com/lcontreras48/kubit/issues/7).

Kubit evaluates cluster components against claims made by official upstream
projects. Those upstream documents remain the authority for a compatibility
claim. This design introduces a versioned, validated feed as Kubit's
operational source of truth so that a cluster scan does not depend directly on
the current layout or availability of an upstream web page.

## Terminology and authority

The design distinguishes three kinds of data:

- **Official evidence** is an upstream policy, support matrix, release, chart,
  or other project-owned document. It is the authority for a compatibility
  claim.
- **Raw evidence** is the immutable byte-for-byte document retrieved by the
  ingestion process, together with its provenance and checksum.
- **Normalized evidence** is a validated Kubit rule derived from raw evidence.
  Published normalized evidence forms the compatibility feed consumed by the
  runtime.

The feed does not create compatibility claims and cannot make unofficial data
authoritative. Every rule must be traceable to official evidence. Missing,
expired, invalid, or unverifiable evidence must not produce a `supported`
result.

## Current behavior

Providers currently fetch upstream documents and parse them in the Kubit
runtime. A provider stores one JSON snapshot containing normalized rules, the
source URL, retrieval time, and a checksum of the source content. When a fetch
or parse fails, the provider uses that snapshot until it becomes stale.

This gives Kubit a useful last-known-good fallback, but it has limitations:

- each provider snapshot replaces the previous snapshot;
- the original source content is not retained;
- a historical document cannot be parsed again with a corrected parser;
- cluster scanning, upstream retrieval, and parsing share one process;
- every Kubit installation independently interprets mutable upstream pages;
- a local ReadWriteOnce cache limits safe horizontal scaling.

## Target architecture

The target separates evidence production from evidence consumption:

```text
official upstream sources
          |
          v
  evidence ingestion
          |
          +----> immutable raw documents
          |
          v
 parsing and validation
          |
          v
 candidate feed revision
          |
          v
 promotion of last-known-good revision
          |
          +----> immutable OCI artifact
          +----> HTTPS discovery index
          |
          v
   Kubit feed reader
          |
          v
 compatibility engine
```

Evidence ingestion may initially run inside Kubit while the storage format is
stabilized. The interfaces and data format should nevertheless keep ingestion
separate from runtime consumption. A later phase can run ingestion in GitHub
Actions, a scheduled Kubernetes workload, or a dedicated service without
changing the compatibility engine.

## Feed envelope

The example below documents the intended information model. It is not a final
JSON Schema; field names may change during maintainer review.

```json
{
  "schema_version": 1,
  "feed_revision": "sha256:<canonical-feed-digest>",
  "generated_at": "2026-11-21T12:00:00Z",
  "expires_at": "2026-11-28T12:00:00Z",
  "providers": [
    {
      "name": "cloudnativepg-supported-releases",
      "parser_version": "2",
      "retrieved_at": "2026-11-21T11:55:00Z",
      "source": {
        "requested_url": "https://example.invalid/upstream/main/support.md",
        "resolved_url": "https://example.invalid/upstream/<commit>/support.md",
        "revision": "<upstream-commit>",
        "media_type": "text/markdown",
        "etag": "<upstream-etag>",
        "last_modified": "<upstream-last-modified>",
        "sha256": "<raw-document-digest>"
      },
      "rules": []
    }
  ]
}
```

The feed revision must be computed from a deterministic canonical encoding.
Provider ordering, rule ordering, timestamps, and optional fields must have
documented normalization rules so that identical input produces identical
content.

Raw documents should be stored by content digest instead of by provider name:

```text
raw/sha256/<digest>
feeds/sha256/<feed-revision>.json
channels/stable.json
```

The stable channel is a small pointer to an immutable revision. Publishing a
candidate must never overwrite or mutate an already published revision.

## Ingestion and validation

An ingestion run performs the following steps:

1. Retrieve the official source over HTTPS with bounded size and timeouts.
2. Record the requested and final URLs, redirect chain, response metadata, and
   retrieval time.
3. Resolve mutable source references such as `main`, `master`, or `stable` to
   immutable commit identifiers when the upstream service supports it.
4. Store the exact source bytes under their SHA-256 digest.
5. Run the declared parser version against those stored bytes.
6. Validate the candidate against the feed JSON Schema and semantic rules.
7. Compare the candidate with the current stable revision.
8. Publish the immutable candidate and promote it only after all required
   policy checks pass.

At minimum, semantic validation should reject:

- duplicate provider or rule identifiers;
- rules without an official HTTPS evidence URL;
- an empty result from a provider that previously produced rules;
- malformed versions, dates, constraints, or unsupported rule types;
- a source digest that does not match the stored raw bytes;
- a parser version change without an explicitly generated new revision;
- loss of a large portion of a provider's rules without acknowledgement.

Large or surprising diffs should require maintainer review instead of being
promoted automatically. The exact threshold is a policy decision and should
be configurable per provider.

## Runtime resolution and failure behavior

The runtime should resolve evidence in this order:

1. a configured and verified stable feed revision;
2. the locally persisted last-known-good feed;
3. a bootstrap feed packaged with the Kubit release.

The bootstrap feed is for initial availability, not indefinite freshness. All
three sources use the same schema and validation path.

| Condition | Runtime behavior |
| --- | --- |
| New feed is valid and within its freshness window | Persist and evaluate it |
| Feed endpoint is unavailable | Use the local last-known-good revision and expose `cached` |
| Feed is older than its expiry | Keep provenance visible, expose `stale`, and do not produce new supported claims from it |
| Feed digest or signature is invalid | Reject it, retain the previous valid revision, and alert |
| Feed schema is newer than the runtime supports | Reject it and retain the previous valid revision |
| No valid local or bootstrap feed exists | Mark affected evidence unavailable and return `unknown` |
| One provider candidate fails ingestion | Keep that provider's previous stable revision; do not partially promote invalid data |

Feed refresh must be independent of cluster inventory changes. A change in the
observed cluster may select different rules from the same feed, but it must not
force all upstream sources to be fetched again.

## Provenance exposed by Kubit

Reports, metrics, and the **Sources of Truth** view should eventually expose:

- feed revision and channel;
- feed generation, retrieval, and expiry times;
- provider name and parser version;
- requested URL and immutable resolved source revision when available;
- raw evidence checksum;
- feed verification status;
- whether the active data is fresh, cached, stale, bootstrap, or unavailable.

This allows an operator to reproduce the rule that produced a result and to
distinguish upstream evidence age from the time Kubit downloaded the feed.

## Publication and trust

The proposed distribution mechanism is an immutable OCI artifact in GHCR,
matching Kubit's existing release infrastructure. A small HTTPS index may
advertise the current stable digest, but the digest—not the mutable index—is
the identity of a feed revision.

Before remote publication is implemented, maintainers should decide:

- who is authorized to promote a stable revision;
- whether promotion requires code-owner approval or an environment approval;
- whether OCI artifacts must be signed and which identity is trusted;
- how signing keys or workload identities are rotated;
- how long raw documents and superseded feed revisions are retained;
- whether installations may pin a feed digest or channel.

Consumers must verify the advertised digest before parsing the document. Feed
data is untrusted input even when transport and signatures are valid, so the
existing size, URL, and parser bounds remain necessary.

## Incremental delivery

The change should be delivered as focused pull requests:

1. **Design and contracts.** Agree on authority, lifecycle, failure semantics,
   and rollout. Add a JSON Schema after the envelope is approved.
2. **Immutable local history.** Preserve raw documents and multiple snapshot
   generations while keeping existing runtime behavior.
3. **Deterministic feed builder.** Generate and validate candidate feed
   revisions from stored documents; add golden and corruption tests.
4. **Reader boundary.** Make the engine consume a `FeedReader` and decouple feed
   refresh from cluster inventory refresh.
5. **Dual-read migration.** Keep direct providers as the default, optionally
   evaluate the feed in shadow mode, and report differences without changing
   compatibility results.
6. **Controlled cutover.** Enable feed consumption by configuration, retain a
   direct-provider rollback path, and document operational migration.
7. **Publication.** Add scheduled generation, approval-based promotion, OCI
   publication, verification, retention, and rollback procedures.

Each behavior-changing pull request must include failure-path tests. The
cutover should happen only after shadow-mode output is equivalent for the
supported providers and maintainers approve the operational model.

## Open decisions

Maintainer approval is required before implementation commits to these choices:

- whether provider revisions are promoted independently or only as an atomic
  complete feed;
- the canonical JSON encoding and schema evolution rules;
- automatic-promotion thresholds and manual approval policy;
- GitHub Actions, a scheduled service, or both as the ingestion environment;
- OCI signing and verification requirements;
- retention limits for raw evidence and feed history;
- behavior of an expired bootstrap feed during a first offline installation.

