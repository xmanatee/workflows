# Application releases

`python3 .release/deploy.py` in an enrolled app checks and builds committed,
pushed `main`, qualifies its production image, and publishes an immutable GitHub
Release. Ansible consumes `release.json` and the image digest.
Uncommitted work never enters a release. With the project's pinned Node and
package manager selected, `npm run deploy` or `pnpm run deploy` calls the same publisher.
`python3 .release/deploy.py status` reports whether the committed revision is published.

Requirements: Python 3.12+, GitHub CLI authenticated with repository and package
publishing access, Docker/Buildx, and the Node version in the app's `.nvmrc`.
The package manager comes from its exact `packageManager` pin (pnpm 11 or newer).
Dependencies use frozen installation and local stores; speech assets can reuse a verified local cache.
Successful local builds survive a failed publication in the private artifact cache;
retrying verifies their hashes and resumes publication. Publication removes that cache.
Local image scans serialize access to the shared Trivy cache across repositories.
All downloads of executable tooling have pinned versions and checksums.
Local `deploy`, `verify`, `publish` and `fix` queue behind the monorepo's
`tools/heavy` admission lock and run at utility priority; hosted runners are dedicated.

## Pinning and CI

`.release/deploy.py` is an application's only publisher pin: it downloads
`release.py` at `REF` from this public repository and checks `SHA256`. Every
application commits `.github/workflows/web-release.yml` byte for byte as
`python3 .release/deploy.py template` prints it; its steps only call the deploy
command (`status`, `verify`, `publish`, `audit`, `fix`, `apply-fix`, `refresh`).
Jobs holding a write token never install, build or run dependency code: `publish`
uploads a verified artifact, `apply-fix` commits a qualified lockfile, and `refresh`
moves the pin.
After its tests, this repository's CI publishes an immutable `publisher-<commit>`
release carrying `publisher.json` (`ref`, `sha256`, and the `template` and `deploy`
command digests). The weekly `refresh` job adopts the newest such release that
descends from the current pin and whose template and deploy-command digests match
the application's committed files, by committing the two pin lines to `main` as
`github-actions[bot]`, then dispatches the release. `GITHUB_TOKEN` cannot change
workflow files, so a release that changes either fails `refresh` and the daily audit
with an owner-action message: `python3 release.py adopt <app>...` from a committed,
pushed checkout of this repository writes the pin and template into each application;
review and commit them there.

## Standards

`conform` has two parts. The static part needs no install or build and runs in
every verification and in the daily scheduled audit: package scripts (`check`
stays light; `check:all` and every heavy entrypoint such as bench, e2e, browser or
image-build scripts run through `tools/heavy`), one exact package manager and
lockfile, private packages, the uniform 7-day release-age cooldown
(`min-release-age=7` in `.npmrc`, or `minimumReleaseAge: 10080` in
`pnpm-workspace.yaml`), the audit command, health declarations, the committed CI
template and deploy command, and the nginx Content-Security-Policy. The bundle
part runs after the build: no telemetry or external index assets, every health
marker present, and the event client present when `browserEvents` is true.

The CSP must name every origin. Third-party script origins need
`scriptOrigins: {"https://origin": "reason"}`, and `'unsafe-eval'` or
`'unsafe-inline'` in a script directive needs `scriptExceptions: {"unsafe-eval": "reason"}`;
unused declarations fail. Policies need `object-src 'none'`, `base-uri 'self'` or
`'none'`, and `frame-ancestors` of `'none'`, `'self'` or named HTTPS origins.
`customApiEndpoints: true` alone permits `connect-src https:` for user-configured APIs.

## Health

`.release/config.json` `health` lists `{host, path, file, marker}` checks, with
`"sso": true` for SSO-protected hosts. Markers become literal Gatus body patterns:
1-128 printable ASCII characters without edge spaces, `$ * ? [ ] \`, or a
space-delimited comparison operator. Qualification requires each marker in its
output file and each response on the native amd64 host to equal that file's bytes.
The manifest (policy 2) carries `health: [{host, path, sha256, marker[, sso]}]`,
which the deployment gate requests through the edge and monitoring polls.

## Dependency audits and security fixes

The config's `audit` argv is the dependency gate for both release verification
and `python3 .release/deploy.py audit`. The daily scheduled job runs that gate and
the static standards against the committed lockfile with the pinned manager,
without installing app dependencies, building or publishing; the dependency audit
gets no credentials, and a read-only token only checks publisher adoption.
An existing immutable release never skips this audit. When it fails, the same
read-only job runs `fix`: the manager's lockfile-only fix (`npm audit fix
--package-lock-only` or `pnpm audit --fix=update`, both under the committed cooldown),
refusing any change outside the lockfile, re-auditing and committing locally. It
uploads the lockfile and records the commit's tree before `verify` installs and
builds that commit. Only then does a separate write job run `apply-fix`, which
installs and builds nothing: it accepts exactly the lockfile, requires the recorded
tree, fast-forwards `main` as `github-actions[bot]` and dispatches the release.
Fixes that need manifest changes stay reviewed source changes and leave the
scheduled run failing, as does a failed audit with no dependency finding.

## Sources

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

`browserEvents: true` declares that the app vendors the first-party error client
posting to its own origin's `/_/events`; the edge routes that path to Jump's beacon
only for hosts listed in the servers inventory.

## Images

The publisher scans committed source for secrets, runs `check`, preserves the app's
dependency/license/SBOM gates, builds once, checks required output and hashes the
artifact. It builds a copy-only amd64 image from a pinned nginx base, checks the
exact digest on native amd64, and scans high/critical fixable vulnerabilities before
publishing. Failed qualification never becomes a deployable release. Images must
be private. Provider build credentials stay local or in the existing GitHub secrets.
This repository scans the pinned base daily and weekly moves it to the newest
patch of its nginx line that has been published for 7 days: `refresh-base` scans
and tests the candidate without write credentials, then `apply-base` commits only
that pin line.

Each static output directory occupies an independent image layer. Apps may declare
`immutableDirectories` for top-level output directories whose URLs change whenever
their content changes. Their timestamps are normalized so unchanged assets, including
speech models, share layers across cold builds. Other files retain modification times
for HTTP cache validation.

On ARM, configure a native qualification host once in
`~/.config/app-releases/config.json`, for example `{"qualifier":"server@your-host"}`,
or set `RELEASE_QUALIFIER`. The existing controller host can perform this short
container check over SSH using its own read-only registry identity. It does
not build the app or receive the laptop's publishing credentials. Temporary
containers, credentials and newly pulled qualification images are removed.
Native amd64 CI qualifies locally.

## Publication

Release tags are `release-<full-source-SHA>`. A complete immutable release skips
installation, checks, build and publication. Drafts and incomplete releases fail
explicitly. An atomic `release-publication-lock` Git branch serializes local and
hosted publishers; the winner rechecks publication. Locks are removed on normal
failure/signals and never expire automatically. After a power loss, inspect the
claim commit (host and PID), confirm its publisher has stopped, then remove that
branch before retrying. Do not delete a live publisher's claim. A failed draft must
be inspected and removed before retrying that revision.

Only a release still matching remote `main` may become `latest`; a slower old build
cannot move deployment backwards. Published does not mean installed: the
controller must reconcile successfully. Rollback remains an explicit operational
choice using retained immutable releases.

Projects with provider-specific or signed native releases retain their own flows.
No application secrets, registry service or deployment daemon live in this repo.
