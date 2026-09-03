# Atlas - A Vibe Coder Resource

Atlas is a local-first codebase analysis tool for JavaScript and TypeScript
projects. It turns a repository into deterministic, verifiable maps of files,
relationships, findings, and operational risks without executing the project
being analyzed.

The name is a small VCR joke: **Vibe Coder Resource**.

## Why Atlas?

Large or unfamiliar codebases are difficult to reason about safely. Atlas
creates an evidence bundle that helps you:

- map files, symbols, imports, entrypoints, and reachability;
- compare API, data, environment, and deployment contracts;
- identify cleanup candidates and operational risks;
- inspect, query, diff, and review findings without rescanning; and
- export a self-contained offline viewer for an approved run.

Atlas favors explicit uncertainty over confident guesses. Unsupported or
dynamic behavior becomes a diagnostic or an incomplete-health result instead
of a fabricated finding.

## Project status

Atlas is early public software. The current source version is `0.2.0`; APIs,
schemas, and artifact formats may change before `1.0`. The npm package is not
published, so install and run Atlas from source for now.

## Safety model

Atlas treats the target repository as untrusted input. During analysis it does
not run the target's builds, tests, package scripts, hooks, imported plugins, or
application code. The Atlas runtime does not upload source or artifacts to a
hosted service.

Generated output can still contain sensitive file paths, identifiers, and
source-derived evidence. Keep workspaces outside the analyzed repository,
review exported artifacts before sharing them, and run Atlas with the least
privilege needed. See [Consent and egress boundaries](./docs/CONSENT-AND-EGRESS.md)
and the [threat and data policy](./docs/THREAT-AND-DATA-POLICY.md).

## Requirements

- Node.js 22 or newer
- npm 10
- Git available from a trusted absolute directory on `PATH`

## Quick start

Clone the repository, then install and build it:

```sh
git clone https://github.com/NotADevIAmaMeatPopsicle/atlas-a-vibe-coder-resource.git
cd atlas-a-vibe-coder-resource
npm ci
npm run build
```

Run Atlas against the bundled synthetic example:

```sh
node dist/src/cli.js scan --target examples/minimal-js-ts-repository.target.json --profile examples/minimal-js-ts-repository.profile.json --workspace .atlas-workspace
```

The command emits JSON containing the new `runDirectory`. The example
intentionally exercises an incomplete analysis-health state. It exits with status `2`,
which means the artifacts are valid but require review. Verify them with:

```sh
node dist/src/cli.js verify <run-directory>
```

To analyze your own repository, copy the example target and profile files,
point the target descriptor at your checkout, and tailor the profile's include
roots, entrypoints, exclusions, aliases, and expectations. Keep the target
descriptor and Atlas workspace outside the target repository.

Every target descriptor must make three local-operation permissions explicit:
`agentReview`, `projectMemory`, and `export`. Start with all three set to
`false`; enable only the operation you intend to use.

## Explore a run

```sh
# Human-readable overview
node dist/src/cli.js inspect <run-directory> --format text

# Search verified run data
node dist/src/cli.js query <run-directory> --text "authentication"

# Create and verify an offline viewer (requires export consent)
node dist/src/cli.js viewer create <run-directory> --workspace <workspace> --target <target.json> --output <viewer-directory>
node dist/src/cli.js viewer verify <viewer-directory>
```

The CLI also supports changed-scope reports, finding diffs, regression checks,
historical-evidence indexes, local memory lookup, and review campaigns. Run
`node dist/src/cli.js --help` or read the
[CLI reference](./docs/CLI-REFERENCE.md) for the complete command and exit-code
contract.

## Development

```sh
npm ci
npm run check
```

`npm run check` compiles the project, runs the complete test suite, validates
the npm archive allowlist, checks Markdown links, and audits the repository and
reachable Git history for sensitive material.

The JavaScript API is ESM-only. Use `import` from an ES module; CommonJS callers
must use dynamic `import()`.

## Scope and limitations

- Analysis is static and currently focused on JavaScript and TypeScript
  repositories.
- Findings are review candidates, not proof of runtime behavior,
  exploitability, or business impact.
- Dynamic loading, generated configuration, and unsupported framework patterns
  can reduce coverage; Atlas records those limits rather than silently claiming
  completeness.
- Viewer serving is loopback-only. Creating an export does not authorize
  sharing or publication.

## Documentation

- [Local development](./docs/LOCAL-DEVELOPMENT.md)
- [CLI reference](./docs/CLI-REFERENCE.md)
- [Schema bundle](./schemas/v1/README.md)
- [Consent and egress boundaries](./docs/CONSENT-AND-EGRESS.md)
- [Threat and data policy](./docs/THREAT-AND-DATA-POLICY.md)
- [Public source and package manifest](./docs/PUBLIC-SOURCE-MANIFEST.md)
- [Dependency and license review](./docs/DEPENDENCIES.md)
- [Contributing](./CONTRIBUTING.md)
- [Security policy](./SECURITY.md)

## License

Atlas is available under the [Apache License 2.0](./LICENSE).
