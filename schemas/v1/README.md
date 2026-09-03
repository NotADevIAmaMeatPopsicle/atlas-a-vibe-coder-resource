# Atlas schema bundle v1

These JSON Schema 2020-12 documents are the executable contract for Atlas
configuration, deterministic run artifacts, inspection/query responses,
changed-scope and finding-delta reports, regression corpora, and queued review
campaigns. It also defines fixed-target registration, target-bound finding
dispositions, and cited memory lookup responses. The CLI loads this bundle at
runtime; `verify` applies the record schemas in addition to digest, identity,
count, path, and referential-integrity checks.

`target.schema.json` requires explicit `agentReview`, `projectMemory`, and
`export` booleans. Each gate authorizes only the corresponding local operation;
none authorizes network dispatch, sharing, or publication. Atlas does not
collect runtime evidence or execute target code. The descriptor is operator
policy and must remain a singly linked regular file outside the configured
untrusted target root. Target registration captures the initial permission set
as an immutable maximum, so later descriptor edits can revoke but cannot add a
permission without a fresh workspace and scan.

`profile.schema.json` includes strict `patternExpectations` with minimum and
optional maximum match counts, `fixturePatterns`, exact
`fixtureUnresolvedImports` source-pattern/specifier pairs, configured
`loaderRules`, and per-rule observation/finding expectations. Its
`operationalRisks` object supports legacy `guardPaths`,
`seedDictionarySources`, graph boundary declarations `{id,module,protects}`,
and protected-writer declarations `{id,module,methods}`. Boundaries and writers
must be supplied together; their modules are exact portable paths, while
`guardPaths` remains a fallback hint. Every authored include, exclude,
entrypoint, dead-code-exemption, fixture, guard, and seed-dictionary pattern
receives an implicit nonzero check, as does each path/cohort pattern in a
required loader rule. An explicit expectation for the same collection and
pattern with `minMatches: 0` is the opt-out. Exclusion observations use the
authored pre-pruning boundary. Fixture membership alone does not allowlist
unresolved imports; both the source pattern and raw specifier must match. A
failed observation or target-specific rule expectation belongs to a failed
attempt; it is not published as a successful empty run. Rule minima count
detected observations only, maxima count detected plus uncertain possible
observations, and finding bounds count underlying instances after aggregation.
A bundled corpus-control failure instead disables the affected rule and is
represented in analysis health.

`analysis-health.schema.json` defines the deterministic v1 health record:
run/snapshot binding, profile-pattern observations, per-rule enabled/disabled
state and positive-control counts, labeled broken/fixed incident outcomes,
explicitly synthetic integer recall, a pointer to the separately evaluated
real-target report contract, fixed-case-silence ratios, and catalog/corpus SHA-256
digests. Verification selects one of three exact run contracts: legacy runs
have the original eight files; health-only runs add `analysis-health.json` as a
ninth; and current scans add canonical `triage.md` as a tenth. Unknown extras
are rejected in every mode. The current producer versions are:

| Producer | Version |
| --- | --- |
| Analysis health | `1.3.2` |
| Operational-risk analyzer | `1.3.2` |
| Finding postprocessor | `1.3.0` |
| Triage report | `1.2.0` |
| Viewer | `0.9.0` |

Current scans require exactly one operational marker, one
`profile-observations-v1+sha256...` marker over the canonical observations and
bounded sample paths, the current finding-postprocess marker, and the exact
`triage-report-v1.2.0` marker. A current
`operational-risks-v1.3.2` run cannot omit health or substitute an older
producer. The verifier accepts only the declared health/operational pairs:
`1.3.2`/`1.3.2`, historical `1.3.1`/`1.3.1`, historical `1.3.0`/`1.3.0`, and historical
`1.2.0`/`1.2.2`. Exact pre-operational eight-file and health-only nine-file runs
remain readable, but only the former make no health claim.
The schema bundle is versioned with the source tree. Changes must update the
corresponding producer or verifier version and pass the complete test suite.

For the current producer, verification reruns the bundled controls once per
process and compares the recorded rule/control and incident outcomes with that
fresh evaluation. It also cross-checks per-rule target `findingInstances`
against `findings.jsonl`. Per-rule target state records `inputStatus`; an
observed seeded-dictionary candidate with missing, unmatched, or unusable
configured dictionary input makes that rule and aggregate health incomplete.
A zero-result accidental-protection pass likewise reports incomplete input
because the bounded lexical rule cannot prove absence across runtime or
interprocedural flows.
When a disposition ledger is used, `findingInstances` retains the detector's
pre-disposition count and `suppressedFindingInstances` accounts for the removed
instances. Profile-pattern observations and target detected/uncertain
observation counts are schema-, consistency-, digest-, and manifest-bound, but
are not independently replayed from source because the underlying target
observations are not persisted as a separate artifact. The verifier also
regenerates `triage.md` from the verified run, findings, and diagnostics and
requires byte equality. Current verification fully recomputes surfaced
findings' review IDs, source-hash anchors, priority tuples, and falsifiers. For
suppressed findings it uses structured diagnostic finding/review references to
reconstruct group membership and occurrence numbering; it does not reconstruct
the removed record's complete identity material or anchors.

`incident-corpus.schema.json` validates the bundled labeled synthetic corpus.
The current corpus has 21 mechanism-specific broken/fixed pairs across 9
operational rules; local acceptance detects all 21 broken cases and leaves all
21 fixed cases silent. Evaluated misses or regressions remain failed outcomes,
while an evaluation exception remains a distinct unsupported outcome. The
canonical catalog digest is
`01b5cd020ca20198bed27167fc8bc4942f2de40bc4b16ebc4294895334c27714`
and the synthetic corpus digest is
`038c4b7484a3712ec8b45440c389d6d0243e2be1563ae76012ed3a9767009816`;
both are recorded in analysis health so a result identifies the exact controls
that ran.

`real-target-corpus.schema.json` and
`real-target-corpus-report.schema.json` define a separate static, read-only
regression tier. A corpus pins the repository, full Git revision, object format,
clean/detached requirements, bounded analysis profile, and exact source anchors.
Its report distinguishes `passed`, `failed`, and `not-evaluated`, preserves
diagnostics, and reports real-target recall separately from synthetic health.
The bundled example manifest documents the shape of a four-case real-target
corpus without retaining any private repository contents or provenance. Real
evaluations require an operator-supplied clean, detached checkout and matching
manifest.

`finding.schema.json` permits explicit `defect-candidate`,
`review-inventory`, and `latent-hazard` kinds, stable pattern keys, aggregate
instance counts/anchors, enumerated host/container `mappingContexts`, an
explicit defect `mechanism`, bounded static-only impact context, and auditable
`severityCalibration`. Current findings additionally publish a `reviewId`,
complete sorted `reviewAnchors[{path,sha256}]`, a machine-readable
`static-actionability-v1` `reviewPriority`, and a nonempty
`refutationCondition` distinct from `nextValidation`. The four review fields
are optional together so historical v1 records remain schema-valid; the current
producer requires and the verifier recomputes them. Duplicate review identities
use deterministic `:occurrence:N` suffixes in canonical finding-ID order.
Host/container aggregation uses the rule, exact source
anchor, and mechanism, so contexts that share one source fix remain one
headline. Aggregation happens before the headline finding count. Aggregates promote a primary
top-level `location` when source evidence supplies one; instances are ordered
production-first; and impact
entrypoints are ranked, capped at eight, and record `entrypointRemainder` when
truncated. Optional `counts.findingInstances` in `run.schema.json` separates
presented finding patterns from their underlying instances, and retained member
anchors allow incremental impact/review selection to include an aggregate when
any member changed.

`changed-findings.schema.json` defines the D1 target/run-bound post-filter
report. It binds the verified run and artifact-manifest digest to an exact
target ID, requested and resolved Git revision, observed HEAD, the canonical
in-scope changed-path set, and every matching finding/review identity. This is a
read-only filter over an existing full run, not an incremental scan engine. Its
optional canonical output is immutable and cannot be written inside the target
or source run.

`finding-delta.schema.json` defines the D2 report over compatible verified
baseline and candidate runs. The same target ID compares directly; distinct
registrations require paired descriptors whose run-bound live checkouts exactly
match clean detached Git discovery and share one canonical Git common directory.
Compatibility requires the exact profile, disposition contract, adapter set,
and producer signature. Cross-version comparison is deny-by-default unless both
signatures name one explicit tested declaration; otherwise Atlas returns
`FINDING_DIFF_REBASE_REQUIRED` with an immutable baseline-rescan path. Historical
verification alone does not establish comparison compatibility. Stable
`finding_review_sha256_...` identities omit display locations so
line movement alone does not create a new finding; occurrence indexes retain
duplicates. The report separates new, resolved, and unchanged findings and
records the optional severity gate result. CLI `--output` requires
`--target <target.json>` so output containment can exclude both source runs and
the target; an existing file with different bytes is never overwritten.

`finding-disposition-ledger.schema.json` validates a target-bound review ledger
whose object keys are the stable, occurrence-aware `reviewId` values emitted
directly by current findings (and repeated by finding-delta reports). Each entry
records the emitted finding ID,
one allowed disposition, reviewer, ISO date, supporting evidence, and one or
more exact target-relative path/SHA-256 anchors. A scan suppresses a matching
current finding only when the ledger covers every source path represented by
the finding and every anchor still matches. Changed, missing, incomplete, or
ambiguous anchors retain the finding and produce deterministic diagnostics.
The canonical ledger digest is bound into the run's analysis identity.
Operational rule health retains the pre-disposition detector count and records
`suppressedFindingInstances`; run and viewer verification require the surfaced
instance count plus that suppression count to equal the detector total. Applied,
stale, and anchor-mismatch diagnostics may carry a structured disposition
projection. Applied projections preserve the exact review/finding identity,
decision, reviewer/date/evidence, anchors, and state so triage and viewer output
can show the decision after the finding is suppressed.

`triage.md` has no independent JSON schema. It is a canonical, manifest-hashed
run artifact selected by current `triage-report-v1.2.0`; the verifier recomputes
its shared priority ordering, concise contradiction/action summary, falsifier,
coverage limitations, folded evidence, and inline disposition projection from
the canonical run records. Diagnostics remain summarized by code and severity,
with detailed instances retained in `diagnostics.jsonl`. Historical v1.0.0 and
v1.1.0 triage artifacts remain verifiable through their byte-exact renderers.

CLI scan, run verification, regression verification, viewer creation, and
viewer verification expose health summaries and exit with status `2` when
health is incomplete. `diff --fail-on-new` uses exit `3` for a triggered
finding gate so CI can distinguish a blocking finding delta from incomplete
health. An evaluated real-target miss uses exit `2`; an absent or ineligible
real target remains `not-evaluated` with exit `0`. Viewer `0.9.0`
projects health, review priority/falsifiers, folded evidence, and structured
dispositions, and binds its
data, manifest, and identity to the source run's exact artifact-manifest SHA-256
as well as its analysis markers and control result; the viewer remains a
noncanonical projection.

`attempt.schema.json` describes volatile, host-local execution receipts.
Absolute paths and timestamps are permitted there and are deliberately excluded
from deterministic run identity and artifact manifests.

`target-registration.schema.json` describes the workspace-local, immutable
binding between a target ID, its canonical repository root, and its canonical
descriptor path. Scans register this binding before analysis; review operations
must agree with it so a target ID cannot be silently rebound inside one Atlas
workspace.

`git-discovery.schema.json` describes the bounded, portable Git worktree ledger
sealed into each run. It records HEAD/object-format provenance plus tracked,
untracked, ignored, changed, conflicted, renamed, and gitlink states without
entering submodules or invoking hooks, filters, package scripts, or network
protocols.

`memory-lookup.schema.json` describes the fixed-target JSONL memory response,
including cited hits, byte-level freshness, coverage/unknown markers,
truncation, and explicit source/secret omission flags.

The foundation specification also defines a future full discovery ledger,
capability-completeness records, and richer producer locks. Those structures are
not represented here until the implementation emits and verifies them.
