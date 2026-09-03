# Local development

## Requirements

- Node.js 22 or newer
- npm 10 (the repository records the tested package-manager version)
- Git available from a trusted absolute directory on `PATH`

## Install and verify

From the repository root:

```powershell
npm ci
npm run check
```

The lockfile supplies the complete dependency set. Atlas needs no database,
cloud account, API key, hosted service, Docker daemon, or target build.

## Environment variables

Atlas does not load dotenv files and has no required runtime, build, or test
environment variables. Do not create a root `.env` for normal development.
Configuration is explicit:

- `--target` selects a target descriptor or eligible checkout;
- `--profile` selects analysis configuration;
- `--workspace` selects Atlas-owned local state; and
- viewer host/port use CLI flags and default to `127.0.0.1:4173`.

The example target denies review-packet creation, project-memory queries, and
viewer export by default. Enable only the operation you intend after reading
[Consent and egress boundaries](./CONSENT-AND-EGRESS.md); a permission does not
authorize any external recipient or publication.

The file `examples/minimal-js-ts-repository/.env.example` is deliberately
non-runnable analyzer fixture data. Its `APP_PORT` and omitted
`ATLAS_API_TOKEN` declaration exercise environment-contract detection; they are
not Atlas settings and must not be copied to the project root.

Atlas fixes selected Git and locale variables for deterministic subprocesses,
but teammates do not configure those values. It strips inherited `GIT_*`
configuration where needed and never reads user secrets as application config.

## Local-only data

These paths are ignored and must remain local:

- `.atlas-workspace/`, `.atlas-local/`, other `.atlas-*` workspaces, and generated
  viewer/output directories;
- real `.env` files, npm credentials, private keys, and service credentials;
- editor/agent state; and
- confidential historical target/reference evidence.

Optional historical corpora belong under `.atlas-local/reference/` as described
in [reference/README.md](../reference/README.md). They are not part of the
public repository and are not needed for `npm run check` or normal Atlas use.

## First scan

Run commands from the repository root:

```powershell
$scan = node .\dist\src\cli.js scan `
  --target .\examples\minimal-js-ts-repository.target.json `
  --profile .\examples\minimal-js-ts-repository.profile.json `
  --workspace .\.atlas-workspace | ConvertFrom-Json

node .\dist\src\cli.js verify $scan.runDirectory
```

This fixture intentionally records incomplete analysis health. Both commands
therefore return exit status `2` while still emitting valid JSON and preserving
the run. Atlas reserves status `1` for usage, validation, or operational errors;
see the [CLI reference](./CLI-REFERENCE.md) for the complete exit contract.
