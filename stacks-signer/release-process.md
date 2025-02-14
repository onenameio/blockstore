# Release Process

## Platform support

| Platform                    | Supported                            |
| --------------------------- | ------------------------------------ |
| Linux 64-bit                | :white_check_mark:                   |
| MacOS 64-bit                | :white_check_mark:                   |
| Windows 64-bit              | :white_check_mark:                   |
| MacOS Apple Silicon (ARM64) | _builds are provided but not tested_ |
| Linux ARMv7                 | _builds are provided but not tested_ |
| Linux ARM64                 | _builds are provided but not tested_ |

## Release Schedule and Hotfixes

`stack-signer` releases that add new or updated features shall be released in an ad-hoc manner.
It is generally safe to run a `stacks-signer` from that branch, though it has received less rigorous testing than release branches.
If bugs are found in the `develop` branch, please do [report them as issues](https://github.com/stacks-network/stacks-core/issues) on this repository.

For fixes that impact the correct functioning or liveness of the signer, _hotfixes_ may be issued. These hotfixes are categorized by priority
according to the following rubric:

- **High Priority**. Any fix for an issue that could deny service to the network as a whole, e.g., an issue where a particular kind of invalid transaction would cause nodes to stop processing requests or shut down unintentionally.
- **Medium Priority**. Any fix for an issue that could deny service to individual nodes.
- **Low Priority**. Any fix for an issue that is not high or medium priority.

## Versioning

This project uses a 6 part version number.
When there is a stacks-core release, `stacks-signer` will assume the same version as the tagged `stacks-core` release ([5 part version](../docs/release-process.md#versioning)).
When there are changes in-between `stacks-core` releases, the `stacks-signer` binary will assume a 6 part version:

```
X.Y.Z.A.n.x

X major version - in practice, this does not change unless there’s another significant network update (e.g. a Stacks 3.0 type of event)
Y increments on consensus-breaking changes
Z increments on non-consensus-breaking changes that require a fresh chainstate (akin to semantic MAJOR)
A increments on non-consensus-breaking changes that do not require a fresh chainstate, but introduce new features (akin to semantic MINOR)
n increments on patches and hot-fixes (akin to semantic PATCH)
x increments on the current stacks-core release version
```

## Non-Consensus Breaking Release Process

The release must be timed so that it does not interfere with a _prepare phase_.
The timing of the next Stacking cycle can be found [here](https://stx.eco/dao/tools?tool=2); to avoid interfering with the prepare phase, releases should happen at least 24 hours before the start of a new cycle.

1. Before creating the release, the _version number_ must be determined, where the factors that determine the version number are discussed in [Versioning](#versioning).

   - First determine whether there are any "non-consensus-breaking changes that require a fresh chainstate".
     - In other words, the database schema has changed, but an automatic migration was not implemented.
     - Determine whether this a feature release, as opposed to a hotfix or a patch.
   - A new branch in the format `release/signer-X.Y.Z.A.n.x` is created from the base branch `develop`.

2. Enumerate PRs and/or issues that would _block_ the release.

   - A label should be applied to each such issue/PR as `signer-X.Y.Z.A.n.x-blocker`.

3. Since development is continuing in the `develop` branch, it may be necessary to cherry-pick some commits into the release branch.

   - Create a feature branch from `release/signer-X.Y.Z.A.n.x`, ex: `feat/signer-X.Y.Z.A.n.x-pr_number`.
   - Add cherry-picked commits to the `feat/signer-X.Y.Z.A.n.x-pr_number` branch
   - Merge `feat/signer-X.Y.Z.A.n.x-pr_number` into `release/signer-X.Y.Z.A.n.x`.

4. If necessary, open a PR to update the [CHANGELOG](./CHANGELOG.md) in the `release/signer-X.Y.Z.A.n.x` branch.

   - Create a chore branch from `release/signer-X.Y.Z.A.n.x`, ex: `chore/signer-X.Y.Z.A.n.x-changelog`.
   - Add summaries of all Pull Requests to the `Added`, `Changed` and `Fixed` sections.
   - Update the `stacks_signer_version` string in [versions.toml](../versions.toml) to match this release.

     - Pull requests merged into `develop` can be found [here](https://github.com/stacks-network/stacks-core/pulls?q=is%3Apr+is%3Aclosed+base%3Adevelop+sort%3Aupdated-desc).

       **Note**: GitHub does not allow sorting by _merge time_, so, when sorting by some proxy criterion, some care should be used to understand which PR's were _merged_ after the last release.

5. Once `chore/signer-X.Y.Z.A.n.x-changelog` has merged, a build may be started by manually triggering the [`CI` workflow](../.github/workflows/ci.yml) against the `release/signer-X.Y.Z.A.n.x` branch.

6. Once the release candidate has been built and binaries are available, ecosystem participants shall be notified to test the tagged release on various staging infrastructure.

7. If bugs or issues emerge from the rollout on staging infrastructure, the release will be delayed until those regressions are resolved.

   - As regressions are resolved, additional release candidates should be tagged.
   - Repeat steps 3-6 as necessary.

8. Once the final release candidate has rolled out successfully without issue on staging infrastructure, the tagged release shall no longer marked as Pre-Release on the [Github releases](https://github.com/stacks-network/stacks-core/releases/) page.
   Announcements will then be shared in the `#stacks-core-devs` channel in the Stacks Discord, as well as the [mailing list](https://groups.google.com/a/stacks.org/g/announce).

9. Finally, the following merges will happen to complete the release process:
   - Release branch `release/X.Y.Z.A.n` will be merged into the `master` branch.
   - Then, `release/X.Y.Z.A.n` will be merged into `develop`.
