# Security policy

## Supported versions

Atlas is pre-1.0 software and does not yet publish a stable release line.
Security fixes target the latest commit on `main`.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. Use the private
[Report a vulnerability](https://github.com/NotADevIAmaMeatPopsicle/atlas-a-vibe-coder-resource/security/advisories/new)
workflow in the Security tab. If GitHub does not offer that form, contact a
maintainer privately through a contact method listed on their GitHub profile.

Include the affected revision, relevant command or API, reproduction details,
impact, and any suggested mitigation. Do not include third-party source,
credentials, personal data, or confidential target artifacts.

## Security boundary

Atlas analyzes untrusted repositories without intentionally executing their
code. Operators must still run it with least privilege, keep workspaces outside
targets, protect generated artifacts as potentially confidential, and review
portable outputs before sharing them. Source parsing and analysis run in a
resource-limited worker; a worker timeout or memory failure aborts the attempt
without publishing partial analysis. Imported run, review, and historical
artifacts are byte-, count-, and nesting-bounded before recursive processing;
changed-scope hashing and neighborhood traversal have aggregate work limits.
CLI output visibly encodes terminal controls, and viewer handoffs render dynamic
values as inert Markdown code.
