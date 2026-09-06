# Architecture

Atlas is a local Node.js 22 application with an ESM library API and CLI. It
analyzes JavaScript and TypeScript repositories without importing or executing
the target project.

## Data flow

1. A target descriptor and analysis profile define the target, scope, and local
   operation permissions.
2. Git discovery records repository state without invoking target hooks,
   filters, credential helpers, or network protocols.
3. Snapshot acquisition walks the allowed roots without following links,
   records skipped link boundaries, applies hard file and byte limits, and
   records content hashes without retaining source bodies in the published run.
4. JavaScript and TypeScript parsing and analysis run in a bounded worker
   thread. Static analyzers produce relationships, diagnostics, and candidate
   findings while recording unsupported or incomplete cases explicitly.
5. Post-processing assigns stable review identities and priorities, evaluates
   the bundled regression controls, and renders the canonical triage report.
6. The run is schema-checked, content-addressed, written to a temporary
   directory, verified, and atomically published into the selected workspace.
7. Inspect, query, diff, memory, review, historical-evidence, and viewer tools
   consume verified artifacts rather than trusting workspace files directly.

## Main modules

| Area | Location | Responsibility |
| --- | --- | --- |
| CLI and public API | `src/cli.ts`, `src/index.ts` | Command routing and supported library exports |
| Configuration and target binding | `src/config.ts`, `src/targets.ts` | Schema-backed configuration, consent, and immutable workspace registration |
| Discovery and acquisition | `src/discovery/`, `src/snapshot.ts` | Git state, bounded file census, hashing, and path containment |
| Static analysis | `src/adapters/`, `src/analysis/` | Parsing, relationships, reachability, contract checks, cleanup candidates, and operational risks |
| Run publication and verification | `src/run.ts`, `src/verify.ts`, `src/artifact-contract.ts` | Deterministic identities, immutable artifacts, compatibility, and integrity checks |
| Review workflow | `src/reviews.ts`, `src/review-execution/` | Consent-gated packets and local execution/result ledgers |
| Derived tools | `src/inspect.ts`, `src/query.ts`, `src/memory.ts`, `src/incremental/`, `src/changed-findings.ts`, `src/finding-diff.ts` | Read-only views and comparisons over verified runs |
| Historical evidence | `src/historical-evidence/` | Verification and indexing of separately preserved local evidence |
| Offline viewer | `src/viewer/` | Consent-gated export, verification, and loopback-only serving |
| Contracts and tests | `schemas/v1/`, `tests/`, `corpus/` | JSON Schemas, regression coverage, and synthetic fixtures |

## Trust boundaries

The target tree, filenames, file contents, imported artifacts, and review
responses are untrusted. The target descriptor and Atlas workspace must remain
outside the target root. Atlas does not treat a successful scan as proof that
generated metadata is safe to share: paths, symbols, diagnostics, and findings
may still reveal confidential information.

The worker thread limits parser memory and wall-clock time, but it is not an OS
sandbox. Run Atlas with least privilege against a quiescent checkout when an
untrusted actor could otherwise mutate files during analysis. See the
[threat and data policy](./THREAT-AND-DATA-POLICY.md) for the complete security
model and known limitations.

## Artifact compatibility

JSON Schemas live in `schemas/v1/`, while producer and projection versions are
declared in source. Run manifests bind artifact names, byte counts, and SHA-256
digests. Verification also recomputes identities and current derived artifacts;
older supported projections have dedicated byte-compatible renderers.

Changes to a deterministic projection require a producer-version update and a
compatibility decision. Changes to public commands must update the CLI
reference. `npm run check` enforces the schema documentation, CLI synopsis,
package allowlist, Markdown links, and public-content audit alongside the test
suite.
