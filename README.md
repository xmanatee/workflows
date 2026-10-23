# Application releases

`python3 .release/deploy.py` in an enrolled app checks and builds committed,
pushed `main`, qualifies its production image, and publishes an immutable GitHub
Release. Ansible consumes the existing `release.json` and image digest as before.
Uncommitted work never enters a release. No GitHub Actions minutes are required.
With the project's pinned Node and package manager selected, `npm run deploy` or
`pnpm run deploy` calls the same publisher.
`python3 .release/deploy.py status` reports whether the committed revision is published.

Requirements: Python 3.12+, GitHub CLI authenticated with repository and package
publishing access, Docker/Buildx, and the Node version in the app's `.nvmrc`.
The package manager comes from its exact `packageManager` pin. Dependencies use
frozen installation and local stores; speech assets can reuse a verified local cache.
Successful local builds survive a failed publication in the private artifact cache;
retrying verifies their hashes and resumes publication. Publication removes that cache.
Local image scans serialize access to the shared Trivy cache across repositories.
All downloads of executable tooling have pinned versions and checksums.

`.release/config.json` owns app-specific checks, output paths, licensing evidence
and the private image name. `.release/deploy.py` pins this publisher by commit and
checksum. Local and optional manual GitHub releases call the same implementation.
Verification has read-only access; only the separate publication job gets writes. Hosted publication accepts only main-branch pushes or manual runs.
Heavy local `check:all` suites are not release defaults.

Repositories containing separately operated products can declare `sourceInputs`
as committed files/directories for this product's build context. The publisher
always includes its release configuration, Node pin and nginx configuration.
Only these inputs enter the isolated build and secret scan; this is not a
repository-wide credential audit. Keep operator data and other product releases
outside a frontend build context.

Builds in a nested installation root set `workingDirectory`; all output, evidence
and environment-file paths remain relative to the repository root. `check` and
`build` can name a narrower product's package commands. `environment` holds public
production build values. `submodules` lists initialized Git links to archive at
their committed revisions; local changes in them never enter the artifact.

A separately distributed product can set `channel` to publish
`release-<channel>-<source-SHA>` without changing GitHub's latest release. The
controller must explicitly select that channel. `allowPublicSource: true` is only
for such repositories: source and release metadata stay public, while the runtime
image remains private. A channel release fails if main advances during qualification.
`smoke` can verify several host/path responses against their emitted `file` hashes.

The publisher scans committed source for secrets, runs `check`, preserves the app's
dependency/license/SBOM gates, builds once, checks required output and hashes the
artifact. It builds a copy-only amd64 image from a pinned nginx base, checks the
exact digest on native amd64, and scans high/critical fixable vulnerabilities before
publishing. Failed qualification never becomes a deployable release. Images must
be private. Provider build credentials stay local or in the existing GitHub secrets.

Each static output directory occupies an independent image layer. Apps may declare
`immutableDirectories` for top-level output directories whose URLs change whenever
their content changes. Their timestamps are normalized so unchanged assets, including
speech models, share layers across cold builds. Other files retain modification times
for HTTP cache validation.

On ARM, configure a native qualification host once in
`~/.config/app-releases/config.json`, for example `{"qualifier":"server@your-host"}`,
or set `RELEASE_QUALIFIER`. The existing controller host can perform this short
container smoke check over SSH using its own read-only registry identity. It does
not build the app or receive the laptop's publishing credentials. Temporary
containers, credentials and newly pulled qualification images are removed.
Deployment itself still follows Ansible polling. Native amd64 CI qualifies locally.

Release tags are `release-<full-source-SHA>`. A complete immutable release skips
installation, checks, build and publication. Drafts and incomplete releases fail
explicitly. An atomic `release-publication-lock` Git branch serializes local and
hosted publishers; the winner rechecks publication. Locks are removed on normal
failure/signals and never expire automatically. After a power loss, inspect the
claim commit (host and PID), confirm its publisher has stopped, then remove that
branch before retrying. Do not delete a live publisher's claim. A failed draft must
be inspected and removed before retrying that revision.

Only a release still matching remote `main` may become `latest`; a slower old build
cannot move deployment backwards. Published does not mean installed: the existing
controller must reconcile successfully. Rollback remains an explicit operational
choice using retained immutable releases.

Projects with provider-specific or signed native releases retain their own flows.
No application secrets, registry service or deployment daemon live in this repo.
