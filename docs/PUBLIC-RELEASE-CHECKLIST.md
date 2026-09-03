# Public release checklist

This repository is a private release candidate. Its only approved remote is the
private GitHub review repository, which must remain private until the owners
explicitly approve publication.

## Required approvals

- [x] Choose the Apache License 2.0.
- [x] Confirm the project owner controls the rights required to license the
      original Atlas code under Apache-2.0.
- [x] Approve the project title, **Atlas - A Vibe Coder Resource**, and private
      initial visibility.
- [x] Approve `NotADevIAmaMeatPopsicle/atlas-a-vibe-coder-resource` as the
      GitHub account and repository slug.
- [x] Approve the public Git author name and no-reply email used for the clean
      history.
- [x] Approve the public file manifest and anonymized fixture provenance.
      Review [the proposed manifest](./PUBLIC-SOURCE-MANIFEST.md).
- [x] Approve GitHub Private Vulnerability Reporting as the project security
      channel.

## Security gates

- [x] Keep the shipped target example deny-by-default and expose only consent
      fields backed by implemented operation gates.
- [x] Verify the Atlas runtime has no remote publication or hosted-service path.
- [x] Resolve every finding in the private security review and rerun the full
      verification suite.
- [x] Run the full build and test suite on the final candidate.
- [x] Scan the current candidate tree and reachable history for secrets, private
      keys, personal data, private repository identifiers, internal tasks, and
      workstation paths; run `npm run verify:public` and complete a human review.
- [x] Repeat `npm run verify:public` after the approved license and public
      metadata are added to the final candidate.
- [x] Review the locked dependencies, licenses, and production audit result.
      See [the dependency review](./DEPENDENCIES.md).
- [x] Enforce and run the `npm pack --dry-run` public archive allowlist.
- [x] Validate the packed ESM-only API with Publint and the ESM-only profile of
      Are the Types Wrong.

## Publication gates

- [x] Add the approved `LICENSE`, author, title, and license metadata.
- [x] Add the approved repository, homepage, and issue URLs to package metadata.
- [x] Create a new private, empty GitHub repository with no inherited history.
- [x] Push only this clean `main` branch, never `--all` or `--mirror`.
- [x] Confirm the private remote contains the exact local commit and file set,
      with no additional branches or tags.
- [ ] Change visibility only after explicit approval from both project owners.
