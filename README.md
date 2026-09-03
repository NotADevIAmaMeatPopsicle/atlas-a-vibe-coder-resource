# Atlas - A Vibe Coder Resource

Atlas is a local-first, evidence-backed analysis tool for JavaScript and
TypeScript repositories. It builds deterministic snapshots, maps static
relationships, reports bounded findings and diagnostics, and produces
verifiable local review artifacts without executing the target project.

## Release status

This repository is a private public-release candidate. It has fresh Git history,
contains only the proposed public core, and is mirrored only to the approved
private GitHub review repository. Do not change visibility, create a release,
or publish the npm package until every item in
[the public-release checklist](./docs/PUBLIC-RELEASE-CHECKLIST.md) is approved.

Atlas is licensed under the [Apache License 2.0](./LICENSE). The license grant
does not authorize publication of this release candidate; the repository and
package publication locks remain in place until the owners give final approval.

## Requirements

- Node.js 22 or newer
- npm 10
- Git available from a trusted absolute directory on `PATH`

## Install and verify

```sh
npm ci
npm run check
```

The JavaScript API is an ES module. Use `import` from ESM code; CommonJS callers
must use dynamic `import()`. The `atlas` executable remains available through
the package's `bin` entry.

## First scan

```sh
npm run build
node dist/src/cli.js scan \
  --target examples/minimal-js-ts-repository.target.json \
  --profile examples/minimal-js-ts-repository.profile.json \
  --workspace .atlas-workspace
```

The bundled example deliberately produces valid artifacts with incomplete
analysis health, so `scan` exits with status `2`. This is a review-required
result, not an execution failure. The JSON response contains the run directory;
verify it with `node dist/src/cli.js verify <run-directory>`, which also exits
`2` while that recorded health remains incomplete.

Run `node dist/src/cli.js --help` for the complete command synopsis. See the
[CLI reference](./docs/CLI-REFERENCE.md) for command groups, output contracts,
and exit statuses.

Atlas writes its state outside the analyzed target and refuses target-contained
workspaces. Generated workspaces, viewers, logs, credentials, local databases,
and historical reference corpora are excluded by `.gitignore`.

## Capabilities

- deterministic file, relationship, finding, diagnostic, and health artifacts;
- static JavaScript and TypeScript relationship analysis;
- API, data, deployment, cleanup, reachability, and operational-risk analysis;
- immutable run verification, inspection, comparison, and review workflows;
- offline viewer bundles served only on loopback; and
- synthetic and operator-supplied real-target regression manifests.

Atlas is a static evidence system. Findings are candidates for review, not
proof of runtime behavior, exploitability, or business impact.

## Documentation

- [Local development](./docs/LOCAL-DEVELOPMENT.md)
- [CLI reference](./docs/CLI-REFERENCE.md)
- [Consent and egress boundaries](./docs/CONSENT-AND-EGRESS.md)
- [Public source and package manifest](./docs/PUBLIC-SOURCE-MANIFEST.md)
- [Dependency and license review](./docs/DEPENDENCIES.md)
- [Threat and data policy](./docs/THREAT-AND-DATA-POLICY.md)
- [Schema bundle](./schemas/v1/README.md)
- [Contributing](./CONTRIBUTING.md)
- [Security policy](./SECURITY.md)
