# Kubit development continuity

Before making changes in this repository:

1. Read `README.md`.
2. Read `docs/DEVELOPMENT_STATUS.md` completely.
3. Check this working tree and the deployment repositories at
   `../../kubit`, `../../ics-docker/kubit`, and `../../argocd`; do not overwrite
   unrelated or uncommitted work.

Repository boundaries:

- This GitHub repository is the single source of truth for Kubit application
  development. It owns source, tests, the Dockerfile, release automation, the
  Helm chart, generic Kustomize resources, and development status.
- `../../kubit` owns only the private ESS sandbox deployment overlay and must
  consume an immutable release from this repository.
- `../../argocd` owns environment-specific Argo CD Applications and private
  cluster integration.
- `../../ics-docker/kubit` is legacy for new releases; do not duplicate source
  or new image-publishing logic there.

Product invariants:

- Compatibility claims require an official evidence URL. Missing evidence must
  produce `unknown`, never inferred support.
- Runtime inventory and compatibility data must be discovered automatically.
  Operators must not upload inventories, enter installed versions, or maintain
  runtime vendor matrices in Git.
- Parser fixtures are test-only and must never become runtime fallback data.
- Kubernetes is the central compatibility axis. Validate its control-plane and
  node components first, then every detected application against the observed
  or proposed Kubernetes version.
- Keep generic public resources free of private cluster names, credentials,
  Vault paths, runtime findings, and environment-specific configuration.

After every material implementation or release change, update
`docs/DEVELOPMENT_STATUS.md` in the same change. Keep it concise and current;
replace stale current-state facts and preserve lasting decisions in its
decision log.
