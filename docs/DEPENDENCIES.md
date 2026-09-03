# Dependency and license review

Atlas uses a small, lockfile-pinned npm dependency tree. The production tree is
used locally for schema validation and static TypeScript parsing; no dependency
is loaded from a target repository.

| Package | Locked version | Scope | License | Purpose |
| --- | ---: | --- | --- | --- |
| `ajv` | 8.20.0 | production | MIT | JSON Schema 2020-12 validation |
| `ajv-formats` | 3.0.1 | production | MIT | Date and date-time format validation |
| `fast-deep-equal` | 3.1.3 | transitive production | MIT | AJV equality helper |
| `fast-uri` | 3.1.7 | transitive production | BSD-3-Clause | AJV URI and schema-reference resolution |
| `json-schema-traverse` | 1.0.0 | transitive production | MIT | AJV schema traversal |
| `require-from-string` | 2.0.2 | transitive production | MIT | `ajv-formats` module helper |
| `typescript` | 5.9.3 | production | Apache-2.0 | Static JavaScript/TypeScript parsing |
| `@types/node` | 22.20.1 | development | MIT | Node.js TypeScript declarations |
| `undici-types` | 6.21.0 | transitive development | MIT | Node.js declaration dependency |

Versions and license identifiers were checked against the installed package
manifests produced by `npm ci` from `package-lock.json`. Dependencies are not
vendored into the npm archive; npm installs their own packages and license
files. Atlas itself is licensed under the Apache License 2.0.

Before publication and on dependency changes, run:

```sh
npm ci --ignore-scripts
npm ls --all
npm audit --omit=dev
npm run check
```

At this review, `npm audit --omit=dev` reports zero vulnerabilities. The lockfile
uses `fast-uri` 3.1.7, which is beyond the 3.1.6 fix boundary for the four URI
normalization advisories that affected the earlier 3.1.5 lock.
