# Public source and package manifest

This document defines the public source boundary. It does not authorize an npm
package release or publication of any target data or generated Atlas artifact.

## Public Git repository candidate

The authoritative candidate is exactly the set reported by `git ls-files` in
this clean repository. It contains:

- root project metadata and community policies;
- TypeScript implementation and tests under `src/` and `tests/`;
- JSON Schemas and their documentation under `schemas/v1/`;
- the deliberately synthetic example under `examples/`;
- synthetic regression manifests under `corpus/`;
- local reference creation/verification and public repository and package
  verification scripts under `scripts/`;
- public design, development, security, and release documentation under
  `docs/`; and
- `reference/README.md`, which documents the boundary for separately held
  historical evidence without including that evidence.

The example repository and bundled corpus manifests are synthetic public test
material. They contain no copied private source or private provenance. The
`corpus/real-target/example-target/manifest.json` file is an illustrative
placeholder and not an observation of a real private repository.

## Excluded local material

The `.gitignore` policy excludes dependency installs, compiler/test output,
Atlas workspaces and viewers, agent/editor state, real environment files,
credentials and private keys, databases, logs, and historical target/reference
evidence. A clean `git status --short --ignored` review is still required before
publication because ignore rules reduce accidents but do not classify content.

In particular, only `reference/README.md` is public under `reference/`; actual
historical evidence belongs under `.atlas-local/reference/` and must never be
copied into the public tree, an issue, or a release artifact.

## npm archive candidate

The package archive is narrower than the Git repository. It includes the
compiled runtime and declarations, schemas, synthetic examples and regression
manifests, user-facing documentation, community policies, and the public helper
scripts needed to create or verify reference manifests. It excludes TypeScript
source, tests, development-only scripts and configuration, installed
dependencies, generated workspaces/viewers, and private reference data.

Run the enforced dry-run check with:

```sh
npm run verify:package
```

The verifier builds the runtime, asks npm for its exact dry-run file list,
rejects files outside the approved path classes, rejects common secret and
database path classes, and requires the CLI, schema, example, documentation,
and reference-manifest helpers. It also confirms that every relative link in the
packaged Markdown resolves to another packaged file. It never creates a tarball
or publishes anything.

Run the broader repository and reachable-history content audit with:

```sh
npm run verify:public
```

That gate checks the current non-ignored tree, every blob reachable from a Git
ref, commit metadata, and every npm archive file for sensitive path classes,
high-confidence credential forms, non-placeholder email addresses, workstation
home paths, and internal task identifiers. It reports only the detector class
and file location, never the matched value. Automated detection supplements the
required human review; it cannot prove that arbitrary text contains no private
or personal information.

The package remains `private: true` as a deliberate npm publication lock. The
Apache-2.0 license and approved author metadata apply to this source repository,
but an npm release requires a separate owner decision. Repository, homepage,
and issue metadata point to the canonical GitHub repository. The local `main`
branch tracks only that destination, and no other branch or tag is published.
