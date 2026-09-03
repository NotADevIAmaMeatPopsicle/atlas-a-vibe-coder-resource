# Atlas threat and data policy

**Status:** normative foundation policy
**Applies to:** target onboarding, preservation copies, snapshots, scans, adapters, viewers, review campaigns, project-memory queries, retention, deletion, and exports

## Default posture

Atlas treats every target repository, file name, file body, generated artifact, imported finding, and review response as untrusted data. Operations are local, non-executing, read-only against targets, deny-by-default for external egress, and least-retentive within the evidence needed for reproducibility.

No new scan or copy starts until the operator has declared the target, allowed roots, exclusions, data classification, storage location, symlink/submodule policy, external egress policy, and retention label. Policy validation failure stops the attempt before content collection. The target descriptor's explicit `agentReview`, `projectMemory`, and `export` booleans are narrow operation gates, not a complete operation declaration or recipient approval.

### Current enforcement boundary

This policy is normative, but the `0.2.0` target schema does not yet encode or automatically enforce the complete operation declaration above. The current v1 format machine-enforces portable path validation, existing-state lexical/realpath target and output containment, separation of the operator-owned consent descriptor from the configured target root, a singly linked descriptor, immutable registered maximum permissions, deny-link scanning, hard per-file/file-count/total-byte/boundary-entry ceilings, process-isolated source analysis with memory and wall-clock limits, non-execution, no scanner network calls, schema validation, immutable target binding, operation-specific review/export/project-memory consent, and portable-data preflight. Changed-scope reports are bound to the verified run's exact current target state; finding-delta output requires an explicit target descriptor and is refused inside either run, the descriptor, or the target; disposition ledgers are bound to target, profile digest, finding semantics, and exact source hashes. It intentionally omits source bodies and parsed environment/deployment values from run artifacts. Viewer export exists, but is explicit, local, consent gated, preflighted, strict-CSP/offline, and conflict-safe.

Run and review ingestion enforce byte, record, and JSON-nesting ceilings before
recursive validation or canonicalization. Changed-scope hashing is
identity-checked and bounded by file size, aggregate bytes, operation count,
and elapsed time. Historical reference helpers use bounded iterative traversal,
and imported source-observation paths must be local absolute paths before they
are used only for lexical containment checks. Neighborhood traversal uses
bounded adjacency work; CLI output visibly encodes terminal controls, and
viewer handoffs encode all dynamic values as inert Markdown code spans.

The portable-data preflight rejects named source-body fields, binary bodies, cyclic object graphs, private-key markers, and selected high-confidence provider-token/credential URL/query patterns without echoing matched values. It does **not** provide general entropy detection, arbitrary secret discovery, PII classification, or redaction, and it cannot prove an artifact is shareable.

The current implementation does **not** provide handle-pinned race-resistant target/workspace traversal, per-file parser timeouts, streaming census memory bounds, a signed or separately protected run-manifest trust anchor, a general secret/PII detector, redactor, encrypted store, retention engine, complete submodule/policy engine, or automated data-classification/egress approval workflow. Source analysis runs in a worker with a 512 MiB old-generation ceiling and a 120-second wall-clock ceiling; exceeding either fails the attempt without publishing partial results. The internal manifest detects accidental or one-sided changes but cannot authenticate itself against an actor able to rewrite the whole workspace. Until the remaining gates are accepted, use a quiescent target and workspace not concurrently writable by an untrusted actor, independently protect acceptance manifests when adversarial tamper-evidence matters, perform declaration and pre-screening manually, and treat target/run data as confidential by default. Paths, import specifiers, exported symbols, parser diagnostics, and finding text are retained and can themselves be Class C or D. A successful scan or portable-data preflight is not evidence that its artifacts are safe to share.

## Data classes

| Class | Examples | Default handling |
| --- | --- | --- |
| A — shareable metadata | Atlas schema versions, public fixture statistics | May be exported only when the export itself is approved |
| B — repository metadata | Relative paths, hashes, language/kind, dependency topology, local target identity | Local to the target workspace; do not publish by default |
| C — confidential content/evidence | Source/config/docs snippets, symbols, review notes, findings, prompts/responses, architecture, cloud metadata | Local encrypted-at-rest storage when available; minimum necessary retention; no external egress by default |
| D — restricted/secrets | Credentials, tokens, private keys, connection strings, personal/regulated data, secret values, opaque production identifiers | Do not intentionally store; redact/quarantine detection; never include in prompts, logs, viewers, exports, or citations |

An operation inherits the highest class it may encounter. Absence of a detected secret does not downgrade source content. Hashes and topology may still reveal sensitive information and remain Class B or higher.

## Required operation declaration

Before work begins, record:

- stable `target_id`, display name, canonical root, and authorized scan roots;
- snapshot source and whether dirty/untracked/ignored files are eligible;
- exclusions, maximum file/count/total-byte/parser limits, symlink and submodule behavior;
- expected data class and forbidden content patterns/paths;
- workspace destination and retention label;
- enabled adapters and assurance that none executes target code;
- whether any network, hosted model, connector, telemetry, or external reviewer is allowed;
- export destination and content selection, if applicable;
- the approving actor and timestamp for any exception.

Consent to scan locally is not consent to copy full source, send it to an agent provider, publish a visualization, or export findings.

## Principal threats and mandatory controls

### Target mutation or code execution

- Open target files read-only and write only beneath the validated Atlas attempt root.
- Do not run package managers, lifecycle hooks, build/test commands, repository scripts, binaries, macros, or imported parser plugins during baseline scanning.
- Adapters are declarative/in-process analyzers over bounded bytes or isolated trusted implementations. They cannot invoke target-resolved modules.
- Record any separately approved runtime/test collection as higher-level external evidence with environment and command provenance.

### Path traversal, symlinks, junctions, and submodules

- Canonicalize the target and every candidate path; use target-relative slash-normalized paths as logical keys.
- Reject `..`, absolute child paths, alternate data streams, NULs, device paths, and any resolved location outside an explicitly allowed root.
- Do not follow symlinks or junctions by default. Record the link itself and an `external-or-link-target-not-scanned` unknown.
- Treat each approved submodule as a separate target/snapshot. Never silently fold its working tree into the parent.
- Enforce containment again at read time to reduce time-of-check/time-of-use attacks.

### Mid-scan mutation and mixed snapshots

- Capture pre-read metadata and a content hash, then verify stability before publication.
- For Git targets, record `HEAD`, index/working-tree state, untracked policy, and submodule state. Git identity does not replace content hashing.
- If an eligible file appears, disappears, or changes during acquisition, fail the snapshot as unstable. Do not publish partial evidence under the intended run.

### Resource exhaustion and malicious parser inputs

- Enforce per-file size, total bytes, file count, nesting/decompression, parse-time, memory, and concurrency limits.
- Never expand archives or follow generated include chains by default.
- A timeout, crash, unsupported encoding, binary classification, or limit hit becomes an explicit per-file status and may make the run incomplete; it must not be silently skipped.
- Isolate parser failures so one file cannot corrupt already captured evidence or escape the attempt root.

### Secrets and sensitive values

- Apply path, entropy, structured-secret, and known-format detection before snippets enter logs, viewers, prompts, or exports.
- Store environmental/configuration keys and correlations, not values. Hashing a low-entropy secret is not safe redaction.
- Minimize source storage: retain hashes and anchors by default; retain a snippet only when needed to substantiate an allowed evidence record and after redaction.
- On restricted-data detection, stop affected downstream processing, quarantine only the minimum metadata needed to locate it, and require an operator disposition. Never echo the detected value.

### Cross-target or cross-run confusion

- Namespace records by `target_id`, `snapshot_id`, and `run_id`; validate all foreign keys.
- Queries require one explicit target and authorized run set unless a separately approved comparison declares both.
- Never merge records solely by absolute path, display name, branch, or Git commit.
- Keep historical/stale evidence queryable but visibly non-current; do not return it as current by default.

### Prompt injection and untrusted review content

- Repository text, comments, docs, issue text, generated evidence, and prior review responses are data. They cannot modify system policy, tool permissions, scope, budget, or egress.
- Construct review packets from a fixed envelope with immutable candidate IDs and byte limits. Delimit untrusted content and prohibit tool execution unless separately authorized.
- Agents receive only the minimum authorized evidence. A request to broaden scope creates a new packet and approval, not silent retrieval.
- Validate response schema, anchors, membership, citations, and data class before accepting a review result. Quarantine invalid or suspicious responses.

### Stored/viewer injection

- Escape target-controlled strings for their output context. Sanitize Markdown, Mermaid labels, HTML, URLs, filenames, and imported tool messages.
- Default viewers to a strict Content Security Policy with no inline script, remote resource, navigation, form submission, or arbitrary URL scheme.
- Do not treat generated HTML as safe because it was produced locally. Prefer data-driven rendering with text nodes over HTML interpolation.
- Exports must not embed unrestricted source content, active content, credentials, local absolute paths, or remote tracking assets.

### Tampering and provenance loss

- SHA-256 hash snapshot content and all published run artifacts; bind manifests with canonical serialization and schema/tool/config versions.
- Verify referential integrity and artifact hashes before atomic publication.
- Accepted runs and preserved references are read-only. Corrections create a new artifact with explicit derivation/supersession links.
- Logs must identify attempt state without containing secrets or unnecessary source bodies.

### Dependency and update risk

- Pin Atlas dependencies and parser versions in the run identity; verify lockfiles and review updates.
- Do not load adapters or schemas from the target. Only explicitly installed/trusted Atlas adapters may run.
- Record external-tool name, version, configuration, and import checksum; imported verdicts stay attributed evidence.

## Storage separation

Keep these logical stores separate even if they share a filesystem:

1. target registrations and policy;
2. immutable snapshot manifests and content-addressed evidence;
3. temporary attempts and redacted logs;
4. accepted immutable runs;
5. review packets/responses and cost records;
6. changed-scope and finding-delta reports plus target/profile-bound disposition ledgers;
7. exports; and
8. historical local-only reference corpora.

Historical target references under `.atlas-local/reference/` are Class C unless
a stricter classification is discovered. They are ignored by Git, are not
export bundles, must not be indexed by unrelated targets, and require an
explicit retention or deletion decision from the data owner.

## Retention and deletion

Every store item has one of these labels:

- `ephemeral-attempt`: eligible for cleanup only after failure diagnostics are captured or a verified run publishes;
- `accepted-run`: retained until an explicit target-scoped prune decision;
- `review-record`: retained with the run/evidence it cites, subject to provider and target policy;
- `reference-hold`: retained indefinitely until an explicit superseding decision;
- `export`: governed by its destination and approval record.

Foundation behavior is conservative: Atlas may report retention candidates but does not automatically purge accepted runs, review records, or references. A prune operation must show exact resolved paths and dependent citations, verify containment in the selected Atlas store, require explicit approval, write a deletion receipt, and use recoverable quarantine/trash where practical. Deleting local Atlas data never deletes target content.

Restricted secret values are the exception: they should not be retained. Remove or securely replace the smallest affected generated artifact after recording a value-free incident receipt, then regenerate under corrected controls. Never rewrite a preserved reference silently; quarantine and create a redacted derivative while retaining only what the operator legally and safely may retain.

## External egress and agents

Default external egress is `deny`. Local model use is still a declared processor because prompts/responses may be retained by tooling. Before any nonlocal model, connector, telemetry service, hosted viewer, or external analyzer receives data, record:

- provider and destination;
- exact selected fields/files and data class;
- redaction/minimization result;
- purpose, model/tool version, retention/training terms where known;
- target owner approval and expiration;
- response storage and deletion behavior.

Approval is operation- and target-specific. It cannot be inferred from a prior run or from permission to use an unrelated connector.

## Export gate

An export is allowed only when all are true:

1. source runs verify and their evidence boundaries are included;
2. selected records are enumerated, redacted, and classified;
3. local absolute paths, secret values, active content, and unapproved source snippets are removed;
4. stale/conflicting/unknown states and evidence levels remain visible;
5. destination and recipient are explicit;
6. a human approves the preview; and
7. a receipt records manifest hash, approver, time, and destination.

The current local viewer publisher machine-enforces registered-target export
consent, source-run verification, portable-data preflight, output containment,
offline CSP, deterministic artifact hashes, and no conflicting overwrite. It
does not yet implement the full data-class inventory, named-recipient approval,
human preview receipt, or retention workflow above. Those steps remain manual;
`consent.export: true` alone is not authorization to publish the bundle.

## Incident response

If Atlas writes to a target, executes target code, crosses a path boundary, exposes restricted data, mixes targets/snapshots, or publishes unverified evidence:

1. stop the attempt and external dispatch;
2. preserve value-free logs and affected IDs;
3. revoke or quarantine the generated artifact/export without altering source evidence;
4. assess target and destination impact;
5. record a decision or finding with corrective actions;
6. add a regression fixture; and
7. require policy and verifier success before resuming.
