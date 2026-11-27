# Contributing to Kubit

Thank you for helping improve Kubit.

## Before you start

- Search existing issues and pull requests before opening a duplicate.
- Discuss large API or architecture changes in an issue first.
- Never add credentials, private cluster exports, or proprietary compatibility
  matrices.
- Compatibility claims must link to official upstream evidence. Missing or
  unverifiable evidence must remain `unknown`.
- Runtime inventory and evidence must be discovered automatically. Parser
  fixtures are for tests only.

## Development checks

Kubit requires Python 3.11 or newer. Run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/set_version.py --check
python3 -m json.tool components/monitoring/dashboard.json >/dev/null
kubectl kustomize base >/dev/null
helm lint charts/kubit
docker build -t kubit:dev .
git diff --check
```

Keep pull requests focused and add tests for behavior changes. Describe the
official evidence used by every new provider and how failures or stale evidence
are prevented from producing a supported result.

## Sign off your commits (DCO)

Every commit in a pull request must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO).
The sign-off certifies that you wrote the change or otherwise have the right to
submit it under the project's license. Add it with `-s`:

```bash
git commit -s -m "Describe the change"
```

This appends a `Signed-off-by: Your Name <you@example.com>` line that must
match the commit author. The DCO check on pull requests fails for commits
without it. To sign off commits you already made:

```bash
git rebase --signoff main
git push --force-with-lease
```

Commits on `main` must also carry a verified signature. Signing your commits
([GPG or SSH](https://docs.github.com/en/authentication/managing-commit-signature-verification))
is recommended; pull requests with unsigned commits are squash-merged, which
GitHub signs. Commits made in the GitHub web interface are signed and signed
off automatically.

By contributing, you agree that your contribution is licensed under the
Apache License 2.0.
