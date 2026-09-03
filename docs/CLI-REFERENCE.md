# CLI reference

This reference covers Atlas `0.2.0`. Build the project, then invoke the
repository-local CLI with `node dist/src/cli.js`. After an approved package
release, the equivalent installed command is `atlas`. Run either form with
`--help` to print the current synopsis.

## Command summary

```text
atlas scan --target <target.json> --profile <profile.json> --workspace <directory> [--dispositions <ledger.json>]
atlas target register --target <target.json> --workspace <directory>
atlas target list --workspace <directory>
atlas verify <run-directory>
atlas changed <run-directory> --target <target.json> --since <git-ref> [--output <report.json>]
atlas diff --baseline <run-directory> --candidate <run-directory> [--fail-on-new info|low|medium|high] [--baseline-target <target.json> --candidate-target <target.json>] [--target <target.json> --output <report.json>]
atlas regression verify [--output <report.json>]
atlas regression real-target [--checkout <detached-checkout> | --target <target.json-or-checkout>] [--corpus <manifest.json>] [--output <report.json>]
atlas inspect <run-directory> [--file <path-or-id> | --symbol <exact-name> | --finding <id> | --neighborhood <path-or-id> [--depth <0-8>] [--direction incoming|outgoing|both]] [--format json|text]
atlas query <run-directory> --text <query> [--limit <count>]
atlas incremental plan --workspace <directory> --target-id <id> --baseline <run-directory> --next <run-directory>
atlas incremental batch --workspace <directory> --spec <batch.json>
atlas historical-evidence index --reference <directory> --manifest <manifest.json> --workspace <directory>
atlas historical-evidence verify <index-directory>
atlas historical-evidence query <index-directory> --text <query> [--limit <count>] [--kind review|trace]
atlas memory lookup <run-directory> --workspace <directory> --target <target.json> --profile <profile.json> --text <query> [--limit <count>]
atlas memory serve <run-directory> --workspace <directory> --target <target.json> --profile <profile.json>
atlas viewer create <run-directory> --workspace <directory> --target <target.json> --output <directory>
atlas viewer verify <viewer-directory>
atlas viewer serve <viewer-directory> [--host <127.0.0.1|::1|localhost>] [--port <port>] [--allowed-host <hostname>]
atlas review create <run-directory> --workspace <directory> --target <target.json> [--selection all|findings|paths|symbols|diff|neighborhood] [--selector <value> | --selectors <array.json>] [--baseline <run-directory>] [--depth <0-8>] [--direction incoming|outgoing|both] [--batch-size <count>] --purpose <text>
atlas review status <campaign-directory>
atlas review execution create <campaign-directory> --max-packets <count> --max-calls <count> --max-tokens <count> --max-time-ms <count>
atlas review execution start|retry <execution-directory> --packet <id> --reviewer-kind human|agent --reviewer <identity> --reviewer-version <version> --prompt-version <version> --token-limit <count> --time-limit-ms <count>
atlas review execution fail <execution-directory> --attempt <id> --input-tokens <count> --output-tokens <count> --duration-ms <count> --failure-code <code> --failure-message <text>
atlas review execution complete <execution-directory> --result <result.json>
atlas review execution pause|resume|status|verify <execution-directory>
atlas version
```

## Output and exit contract

Operational commands emit machine-readable JSON to standard output. The
human-readable exceptions are help, `version`, `inspect --format text`, and the
status messages from the long-running `viewer serve` process. `memory serve`
exchanges one JSON object per line over standard input and output. Failures emit
structured JSON to standard error. Target-controlled terminal characters are
visibly escaped.

- `0`: the command completed and no configured gate requires attention.
- `1`: usage, validation, integrity, or operational failure.
- `2`: valid output requires attention because analysis health is incomplete or
  an evaluated regression failed.
- `3`: `diff --fail-on-new` found a new finding at or above the requested
  severity.

A status of `2` does not invalidate emitted artifacts. Inspect the JSON health
summary and verify the run before deciding whether to accept or replace it.

## Workflow boundaries

`scan` creates an immutable run and registers the target in its workspace.
`verify`, `inspect`, and `query` operate on existing runs. `changed` filters a
verified run to paths changed since a Git reference; `diff` compares compatible
verified runs. Incremental commands plan reusable work but do not mutate target
files.

Review commands create and track local packets and attempts; they do not contact
a reviewer. Historical-evidence commands index and query a separately preserved
local corpus. Memory commands require `consent.projectMemory`; review creation
and execution require `consent.agentReview`; viewer creation requires
`consent.export`. Viewer serving is loopback-only. None of these permissions
authorizes network dispatch or publication.

Output files and directories are immutable: Atlas reuses byte-identical output
where supported and refuses conflicting overwrites. Keep workspaces, viewers,
reports, and historical corpora out of the target and out of source control.
