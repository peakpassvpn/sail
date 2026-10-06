# Releasing sail

A release is made by `.github/workflows/release.yml`, started by hand on
`master`. It builds every file a release ships, checks them, and only then
tags the commit and publishes. This page is how to cut one, and how
versions are numbered.

## Versions

- **Before 1.0**: plain `0.x.y`, published with GitHub's pre-release flag,
  never marked Latest. A release with a breaking change bumps the minor
  (`0.15.0` to `0.16.0`); a release of fixes only bumps the patch
  (`0.16.0` to `0.16.1`).
- **No `-beta` or other suffix before 1.0.** SwiftPM's `from:` ranges pass
  over versions with a pre-release suffix, so an app that depends on
  `from: "0.16.0"` would not see `0.17.0-beta`.
- **From 1.0**: release candidates are `1.0.0-rc.1`, `1.0.0-rc.2`, …,
  published as pre-releases, then `1.0.0`.
- `sail`, `sail-cli` and `sail-ffi` carry the release's version, which the
  Clash and management APIs, the User-Agent, AnyTLS's client name and the
  C ABI report. Other crates keep their own versions.

## Notes

Every release has `docs/releases/<version>.md`, which the release's notes
open with; the workflow refuses to publish without it. The notes start
with **Breaking changes**, or say there are none, then what changed by
area, the files, and how the Swift package and the AAR are used. The
workflow adds the hashes, provenance and size lines after them.

## Cutting a release

1. On a branch: set the version in `sail/Cargo.toml`, `sail-cli/Cargo.toml`
   and `sail-ffi/Cargo.toml`, update `Cargo.lock`, and write
   `docs/releases/<version>.md`.
2. Merge it to `master` as any change: gates, then CI on its `ci/*` branch.
3. Push `master` and wait for its `ci` run to pass: the workflow checks
   that the commit's `ci` run succeeded.
4. Dispatch the release on `master`:

       gh workflow run release.yml --ref master \
         -f version=<version> -f publish=true -f prerelease=true

   (`prerelease=true` for every 0.x and every 1.0.0-rc.N.)
5. The `check` job prints what it will do, for example
   `release v0.16.0: publish=true, gh release edit --prerelease --latest=false, notes docs/releases/0.16.0.md (present)`.
   The release stays a draft until every file is in it, then is
   published; the tag's commit carries `Package.swift` pointing at the
   release's `SailC.xcframework.zip`. Only the tag is pushed.
6. Check the release: every file, `SHA256SUMS`,
   `gh attestation verify <file> -R peakpassvpn/sail`, and that SwiftPM
   resolves the tag.

## A patch release from a tag

When `master` already holds changes that must not ship yet, a patch
release (X.Y.Z+1) is cut from the tag it fixes, with only its fixes:

1. Branch from the tagged release's source commit (the parent of the
   tag's `Package.swift` commit) as `ci/release-X.Y.Z`, the new version.
2. Cherry-pick each fix with `git cherry-pick -x`. Resolve conflicts
   minimally, and say in the commit message what was taken and left.
3. Set the version and write `docs/releases/X.Y.Z.md` as in a release
   from `master`: fixes only, and whether anything breaks.
4. Run the whole matrix on the branch, not just what a push runs:

       gh workflow run ci.yml --ref ci/release-X.Y.Z

5. Dispatch the release on the branch. The workflow publishes from
   `master` or from `ci/release-<version>` only:

       gh workflow run release.yml --ref ci/release-X.Y.Z \
         -f version=X.Y.Z -f publish=true -f prerelease=true

6. Check the release as in step 6 above. Then delete the branch (the tag
   keeps its commits), and add `docs/releases/X.Y.Z.md` to `master` in a
   docs-only commit. `master` does not take the version bump.

## Dry runs

Without `publish`, the workflow is a dry run: everything is built and
checked, and the files stay in the run's artifacts. `apple=false` skips
the macOS runner, for a dry run only; publishing refuses it. A dry run on
a branch (`--ref ci/<name>`) runs that branch's workflow file, as long as
the workflow exists on `master`.

See also: the design behind the workflow (symbols, manifest,
reproducibility checks, the Swift package's tag) is in its comments and in
`scripts/release/`.
