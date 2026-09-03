# Minimal JavaScript/TypeScript Atlas fixture

This deliberately small, non-runnable repository is an acceptance corpus for
Atlas census, parser, reachability, configuration-contract, and candidate
finding behavior. Scanners must inspect it as source text; they must not execute
it or install dependencies.

The adjacent configuration files are:

- `../minimal-js-ts-repository.target.json`
- `../minimal-js-ts-repository.profile.json`

The target descriptor deliberately denies review-packet creation,
project-memory lookup, and viewer export. A user must opt in to a specific
operation; scanning itself does not require those permissions.

## Expected baseline observations

With the adjacent profile, the census contains these ten files:

1. `.env.example`
2. `README.md`
3. `platform/unused-worker.yaml`
4. `src/app.ts`
5. `src/config.ts`
6. `src/format.js`
7. `src/index.ts`
8. `src/lazy.ts`
9. `src/orphan.ts`
10. `test/app.test.ts`

The JS/TS adapter should observe seven import-like declarations:

- Five resolved internal relationships.
- One relationship classified as the external package `node:assert/strict`.
- One unresolved internal relationship for `./missing-internal`.

Exactly one relationship is dynamic: `src/app.ts` imports `src/lazy.ts` with
`import()`.

Starting at the production entrypoint `src/index.ts`, the reachable production
modules are `src/index.ts`, `src/app.ts`, `src/config.ts`, `src/format.js`, and
`src/lazy.ts`. `src/orphan.ts` is therefore an orphan candidate, not proven dead
code. The test file is classified as a test and excluded from source-candidate
analysis; it must not be mislabeled as an orphan.

`src/config.ts` reads `APP_PORT` and `ATLAS_API_TOKEN`. `.env.example` declares
only `APP_PORT`, so `ATLAS_API_TOKEN` is an environment-contract mismatch
candidate. A static result must not claim that the key is absent at runtime.

`platform/unused-worker.yaml` has no source or profile association beyond its
platform component. It is an unused-platform-file candidate, not proof that no
external deployment system uses it.

Unsupported syntax, unresolved targets, and the runtime status of candidate
findings must remain explicit unknowns. No dependency-cruiser output or target
execution is part of this fixture.
