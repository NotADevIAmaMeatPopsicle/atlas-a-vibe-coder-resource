# Security policy

## Supported versions

Atlas has not reached its first public release. Security fixes currently target
the latest commit on `main`.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue. After the GitHub
repository is available, use its private
[Report a vulnerability](https://github.com/NotADevIAmaMeatPopsicle/atlas-a-vibe-coder-resource/security/advisories/new)
workflow in the Security tab. Until that channel is enabled, contact the
maintainers through the existing private project channel.

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
