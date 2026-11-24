# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.5.x (latest release) | Yes |
| `main` | Yes |
| < 1.5 | No |

Security fixes go into `main` and ship in a new patch release of the latest
minor version. Upgrade to the latest release to receive them.

## Reporting a vulnerability

Do not open a public issue, pull request or discussion.

Report privately through either channel:

- GitHub private vulnerability reporting: **Security** tab → **Report a
  vulnerability**
- Email: yanick.egli@linux.com

Include the affected version, reproduction steps, expected impact, and any
suggested mitigation.

Avoid accessing data that is not yours, disrupting clusters, or publishing
details before a fix is available.

## What to expect

- We acknowledge a report within 3 business days.
- We share an initial assessment within 10 business days.
- We keep you updated while we work on a fix.

## Disclosure

- We coordinate disclosure with the reporter. Details stay private until a
  fixed release is available, or for at most 90 days after the report.
- Fixes are published as a GitHub Security Advisory, with a CVE requested
  through GitHub where applicable.
- Reporters are credited in the advisory unless they prefer not to be.
