# Contributing

Issues and focused pull requests are welcome. For broad changes, open an issue
first so the approach and public scope can be discussed before implementation.

## Development workflow

1. Use Node.js 22 and npm 10.
2. Run `npm ci`.
3. Keep real target repositories and `.atlas-*` workspaces outside committed
   paths; only deliberately synthetic fixtures belong in this repository.
4. Make focused changes with corresponding tests.
5. Run `npm run check` before requesting review.

Never commit credentials, private repositories or revisions, customer data,
target source bodies, generated runs, viewer bundles, or historical reference
corpora. Synthetic fixtures must use reserved domains and fictional names.

Security-sensitive changes should document the attacker-controlled input,
trust boundary, expected invariant, and regression test.

Report suspected vulnerabilities privately as described in
[SECURITY.md](./SECURITY.md), not in a public issue.
