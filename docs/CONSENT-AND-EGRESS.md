# Consent and egress boundaries

Atlas performs static analysis locally. Its Node.js runtime does not contact a
hosted service, dispatch review packets, upload artifacts, or execute target
code. Git subprocesses inspect local repository state with hooks, credential
helpers, external diffs, prompts, and nonlocal protocols disabled.

Every target descriptor must explicitly set all three operation-specific
permissions. The public example denies each permission by default:

| Permission | What `true` authorizes | What it does not authorize |
| --- | --- | --- |
| `agentReview` | Create local review packets and start or retry locally recorded review attempts | Sending packets to a model, person, connector, or network service |
| `projectMemory` | Answer local queries from a verified run through the CLI or newline-delimited stdio service | A network listener, cross-target lookup, or external model access |
| `export` | Create a portable viewer directory from a verified run | Serving, sharing, uploading, or publishing that directory |

Atlas has no runtime-evidence collection feature. It never runs target builds,
tests, package scripts, hooks, imported plugins, or application binaries. Any
separately approved runtime collection happens outside Atlas and is not
authorized by a target descriptor.

Because the descriptor carries operator authorization, it must be a regular
file outside the configured target root. Atlas rejects a descriptor stored
anywhere inside that root, even when a junction or relative path would
otherwise escape it. Keep descriptors in an operator-controlled directory
beside the target, as the public example does. If both live inside a broader
version-control checkout, the immutable registration still prevents a later
descriptor edit from granting additional permissions.

Atlas also rejects multiply linked descriptor files so another target-owned
name cannot modify the same consent data.

## Revocation and retained artifacts

Permissions captured by the first registration are an immutable maximum.
Editing `false` to `true` later fails closed; enabling a new operation requires
a fresh workspace and scan. Editing `true` to `false` prevents the corresponding
new operation. Review consent is checked when packets are created and when
review attempts are started or retried. Project-memory consent is checked for
each lookup, including each stdio request. Export consent is checked when a
viewer is created.

Revocation does not erase material already created. Existing review packets,
results, viewer directories, and copied files remain sensitive local artifacts.
Stop any viewer or sharing process and remove or quarantine retained artifacts
under the applicable data-owner decision.

## Migration from earlier local candidates

Earlier pre-release target descriptors included an unused `runtimeEvidence`
field and could omit `projectMemory`. Update them by removing
`runtimeEvidence` and explicitly setting `projectMemory` to `true` or `false`.

All workspaces produced by an earlier local candidate need a fresh registration
and scan because their registration does not contain the new consent maximum.
If the old descriptor was stored inside its target, move it outside first.
Registrations and successful attempt receipts intentionally bind the original
absolute descriptor path, so moving the file cannot silently reauthorize an old
workspace. Existing runs and viewers can still be verified independently, but
new consent-gated operations require the new registration.

## Publication boundary

Creating a viewer is not publication. Atlas does not create a Git remote, push
commits, change repository visibility, or publish an npm package. The
package remains marked `private`, so publishing it requires a separate owner
decision and an explicit metadata change. Repository visibility never grants
permission to publish a target's source, generated workspace, run artifacts, or
viewer output.
