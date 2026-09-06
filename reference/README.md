# Local reference data

Atlas source control intentionally excludes historical target/reference data.
Such corpora are confidential evidence, not application source, and are not a
prerequisite for building, testing, or running Atlas.

Authorized local copies belong under:

```text
.atlas-local/reference/<project>/<capture>/
.atlas-local/reference/manifests/<project>-<capture>.json
```

The reference directory must be an exact, separately made copy of a source
subdirectory in a Git worktree. From the Atlas repository root, create its
manifest outside both the source repository and the copied reference tree:

```powershell
node scripts/create-reference-manifest.mjs `
  --reference .atlas-local/reference/<project>/<capture> `
  --source <absolute-path-to-source-subdirectory> `
  --source-repository <absolute-path-to-source-repository> `
  --out .atlas-local/reference/manifests/<project>-<capture>.json
```

The helper requires the reference directory to be beneath the current working
directory and the source directory to be a proper child of the source Git
repository. It confirms that both trees have identical bounded inventories and
content hashes, then records the repository revision and a value-free digest of
its complete worktree status. It does not copy files.

With both items present, verify them from the repository root:

```powershell
node scripts/verify-reference-manifest.mjs `
  --reference .atlas-local/reference/<project>/<capture> `
  --manifest .atlas-local/reference/manifests/<project>-<capture>.json
```

Both helpers are included in the npm package. They reject links and enforce
bounded directory depth, entry count, file count, per-file bytes, aggregate
bytes, manifest bytes, and JSON nesting before accepting a reference.

Obtain the corpus through the separately approved internal transfer process.
Never commit it, attach it to an issue or release, or copy target `.env` files,
credentials, source bodies, or generated viewer/run data into this directory.
