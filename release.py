#!/usr/bin/env python3
"""The shared local/CI publisher for private static applications (Python 3.12+)."""
import argparse
import base64
import fcntl
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import html.parser
import io
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

POLICY = 2
PUBLISHER = 'xmanatee/workflows'
WORKFLOW = '.github/workflows/web-release.yml'
LEGACY_CALLER = 'xmanatee/workflows/.github/workflows/publish-static.yml'
COOLDOWN_DAYS = 7
BOT = ('github-actions[bot]', '41898282+github-actions[bot]@users.noreply.github.com')
CREDENTIALS = ('GH_TOKEN', 'GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'OPENAI_API_KEY', 'ELEVENLABS_API_KEY', 'HOL_UNLOCK_CODE')
BASE = 'docker.io/library/nginx:1.30.6-alpine-slim@sha256:d9322bba63c6cfc63dc9e86522fd4f95fd4d9020a02b5bced282bbf38b8c3960'
TRIVY = 'ghcr.io/aquasecurity/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c'
TRIVY_DATABASES = ('mirror.gcr.io/aquasec/trivy-db:2', 'ghcr.io/aquasecurity/trivy-db:2')
LEAKS = {
    ('Darwin', 'arm64'): ('darwin_arm64', 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5'),
    ('Darwin', 'x86_64'): ('darwin_x64', 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709'),
    ('Linux', 'aarch64'): ('linux_arm64', 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080'),
    ('Linux', 'x86_64'): ('linux_x64', '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'),
}
ACTIONLINT = {
    ('Darwin', 'arm64'): ('darwin_arm64', 'aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f'),
    ('Darwin', 'x86_64'): ('darwin_amd64', '5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644'),
    ('Linux', 'aarch64'): ('linux_arm64', '325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6'),
    ('Linux', 'x86_64'): ('linux_amd64', '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8'),
}
CACHE = Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'app-releases'
SAFE_ENV = {'DO_NOT_TRACK': '1', 'NEXT_TELEMETRY_DISABLED': '1', 'ASTRO_TELEMETRY_DISABLED': '1',
            'STORYBOOK_DISABLE_TELEMETRY': '1', 'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
            'npm_config_audit': 'false', 'npm_config_fund': 'false', 'npm_config_update_notifier': 'false',
            'DOCKER_BUILD_SUMMARY': 'false', 'DOCKER_BUILD_RECORD_UPLOAD': 'false', 'CI': 'true'}

# Every application commits this workflow byte for byte; its only pin is .release/deploy.py.
TEMPLATE = '''\
name: Web release
on:
  push:
    branches: [main]
  schedule:
    - cron: '17 5 * * *'
    - cron: '47 4 * * 1'
  workflow_dispatch:
permissions:
  contents: read
  packages: read
concurrency:
  group: web-release-${{ github.ref }}
  cancel-in-progress: false
jobs:
  plan:
    if: github.ref == 'refs/heads/main' && github.event_name != 'schedule'
    runs-on: ubuntu-24.04
    timeout-minutes: 3
    outputs:
      published: ${{ steps.status.outputs.published }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - id: status
        env:
          GH_TOKEN: ${{ github.token }}
        run: python3 .release/deploy.py status
  verify:
    needs: plan
    if: needs.plan.outputs.published != 'true'
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
          submodules: true
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1
        with:
          node-version-file: .nvmrc
          package-manager-cache: false
      - uses: astral-sh/setup-uv@56618cab7a58e3efc9b282dd3de75bbf1075db9b
        with:
          version: '0.13.1'
          enable-cache: false
      - uses: actions/cache@caa296126883cff596d87d8935842f9db880ef25
        with:
          path: |
            ~/.npm
            ~/.local/share/pnpm/store
            ~/.cache/app-releases/tools
          key: release-tools-${{ runner.os }}-${{ hashFiles('.nvmrc', '**/package-lock.json', '**/pnpm-lock.yaml') }}
          restore-keys: release-tools-${{ runner.os }}-
      - name: Qualify committed source
        env:
          GH_TOKEN: ${{ github.token }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          ELEVENLABS_API_KEY: ${{ secrets.ELEVENLABS_API_KEY }}
          HOL_UNLOCK_CODE: ${{ secrets.HOL_UNLOCK_CODE }}
          VITE_ELEVENLABS_AGENT_ID: ${{ vars.VITE_ELEVENLABS_AGENT_ID }}
          OPENAI_MODEL: ${{ vars.OPENAI_MODEL }}
          OPENAI_BASE_URL: ${{ vars.OPENAI_BASE_URL }}
          OPENAI_VISION_MODEL: ${{ vars.OPENAI_VISION_MODEL }}
        run: python3 .release/deploy.py verify --artifact "$RUNNER_TEMP/artifact"
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9
        with:
          name: qualified-app
          path: ${{ runner.temp }}/artifact/
          include-hidden-files: true
          if-no-files-found: error
          retention-days: 1
  publish:
    needs: [plan, verify]
    if: needs.plan.outputs.published != 'true'
    runs-on: ubuntu-24.04
    timeout-minutes: 25
    permissions:
      contents: write
      packages: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333
        with:
          name: qualified-app
          path: ${{ runner.temp }}/artifact
      - name: Publish the verified artifact
        env:
          GH_TOKEN: ${{ github.token }}
        run: python3 .release/deploy.py publish --artifact "$RUNNER_TEMP/artifact"
  audit:
    if: github.ref == 'refs/heads/main' && github.event.schedule == '17 5 * * *'
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    outputs:
      tree: ${{ steps.fix.outputs.tree }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
          submodules: true
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1
        with:
          node-version-file: .nvmrc
          package-manager-cache: false
      - uses: astral-sh/setup-uv@56618cab7a58e3efc9b282dd3de75bbf1075db9b
        with:
          version: '0.13.1'
          enable-cache: false
      # Freshly resolved dependencies run here, so this job never saves into the cache verify jobs restore.
      - uses: actions/cache/restore@caa296126883cff596d87d8935842f9db880ef25
        with:
          path: |
            ~/.npm
            ~/.local/share/pnpm/store
            ~/.cache/app-releases/tools
          key: release-tools-${{ runner.os }}-${{ hashFiles('.nvmrc', '**/package-lock.json', '**/pnpm-lock.yaml') }}
          restore-keys: release-tools-${{ runner.os }}-
      - id: audit
        name: Audit committed dependencies, static standards and publisher adoption
        continue-on-error: true
        env:
          GH_TOKEN: ${{ github.token }}
        run: python3 .release/deploy.py audit
      - id: fix
        name: Resolve a lockfile-only security fix
        if: steps.audit.outcome == 'failure'
        env:
          GH_TOKEN: ${{ github.token }}
        run: python3 .release/deploy.py fix --artifact "$RUNNER_TEMP/fix"
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9
        if: steps.fix.outcome == 'success'
        with:
          name: security-fix
          path: ${{ runner.temp }}/fix/
          if-no-files-found: error
          retention-days: 1
      - name: Qualify the fixed lockfile
        if: steps.fix.outcome == 'success'
        env:
          GH_TOKEN: ${{ github.token }}
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          ELEVENLABS_API_KEY: ${{ secrets.ELEVENLABS_API_KEY }}
          HOL_UNLOCK_CODE: ${{ secrets.HOL_UNLOCK_CODE }}
          VITE_ELEVENLABS_AGENT_ID: ${{ vars.VITE_ELEVENLABS_AGENT_ID }}
          OPENAI_MODEL: ${{ vars.OPENAI_MODEL }}
          OPENAI_BASE_URL: ${{ vars.OPENAI_BASE_URL }}
          OPENAI_VISION_MODEL: ${{ vars.OPENAI_VISION_MODEL }}
        run: python3 .release/deploy.py verify --artifact "$RUNNER_TEMP/qualified"
  security-fix:
    needs: audit
    if: needs.audit.outputs.tree != ''
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions:
      contents: write
      actions: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333
        with:
          name: security-fix
          path: ${{ runner.temp }}/fix
      - name: Fast-forward main to the qualified lockfile and request its release
        env:
          GH_TOKEN: ${{ github.token }}
          FIX_TREE: ${{ needs.audit.outputs.tree }}
        run: python3 .release/deploy.py apply-fix --artifact "$RUNNER_TEMP/fix" --tree "$FIX_TREE"
  refresh:
    if: github.ref == 'refs/heads/main' && github.event.schedule == '47 4 * * 1'
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions:
      contents: write
      actions: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - name: Adopt the newest publisher release
        env:
          GH_TOKEN: ${{ github.token }}
        run: python3 .release/deploy.py refresh
'''

DEPLOY = '''\
#!/usr/bin/env python3
"""Run the shared release publisher pinned by commit and checksum."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import urllib.request

REF = "{ref}"
SHA256 = "{sha256}"
root = Path(__file__).resolve().parent.parent
cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "app-releases" / "publishers" / REF
cache.mkdir(parents=True, exist_ok=True)
target = cache / "release.py"
if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest() != SHA256:
    with urllib.request.urlopen("https://raw.githubusercontent.com/xmanatee/workflows/" + REF + "/release.py", timeout=60) as response:
        source = response.read()
    if hashlib.sha256(source).hexdigest() != SHA256:
        sys.exit("Publisher checksum mismatch")
    with tempfile.NamedTemporaryFile(dir=cache, delete=False) as temporary:
        temporary.write(source)
    os.replace(temporary.name, target)
os.execv(sys.executable, [sys.executable, str(target), "--root", str(root), *sys.argv[1:]])
'''


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, *args, **kwargs):
        redirected = super().redirect_request(request, *args, **kwargs)
        if redirected and urllib.parse.urlparse(redirected.full_url).netloc != 'api.github.com':
            redirected.remove_header('Authorization')
        return redirected


def run(args, *, cwd=None, env=None, capture=False, data=None, timeout=900):
    process = subprocess.Popen([str(x) for x in args], cwd=cwd, env=env,
                               stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE if capture else None,
                               stderr=subprocess.PIPE if capture else None, start_new_session=True)
    try:
        stdout, _ = process.communicate(data, timeout=timeout)
    except BaseException:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise
    if process.returncode:
        # Captured commands may handle credentials. Never include their output.
        raise RuntimeError(f'{Path(str(args[0])).name} failed (exit {process.returncode})')
    return stdout if capture else None


def git(root, *args):
    return run(['git', '-C', root, *args], capture=True).decode().strip()


class GitHub:
    def __init__(self):
        self.token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN') or run(
            ['gh', 'auth', 'token'], capture=True).decode().strip()

    def api(self, path, method='GET', body=None, *, missing=False, binary=False):
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/octet-stream' if binary
                   else 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
                   'User-Agent': 'private-app-releases', 'Content-Type': 'application/json'}
        request = urllib.request.Request('https://api.github.com/' + path, headers=headers, method=method,
                                         data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.build_opener(SafeRedirect()).open(request, timeout=60) as response:
                data = response.read()
                return data if binary else json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            raise RuntimeError(f'GitHub {method} {path}: HTTP {error.code}') from None


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def safe_path(root, relative):
    target = (root / relative).resolve()
    if not target.is_relative_to(root.resolve()) or target == root.resolve():
        raise ValueError('Artifact paths must stay inside their source directory')
    return target


def unpack(data, destination):
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        archive.extractall(destination, filter='data')


def archive_source(root, revision, destination, submodules=(), inputs=()):
    excluded = ['.agents', '.claude', '.codex', '.gemini', '.mcp.json']
    paths = list(inputs) if inputs else ['.']
    if inputs:
        paths = list(dict.fromkeys([*paths, '.release', '.nvmrc', 'nginx.conf']))
        for relative in paths:
            safe_path(root, relative)
            if relative.startswith(':') or not git(root, 'ls-tree', revision, '--', relative):
                raise ValueError('Source inputs must name committed files or directories: ' + relative)
    unpack(run(['git', '-C', root, 'archive', revision, '--', *paths,
                *[':(exclude)' + path for path in excluded]], capture=True), destination)
    for relative in submodules:
        original = safe_path(root, relative)
        if git(original, 'rev-parse', '--show-toplevel') != str(original):
            raise ValueError('Initialize the pinned submodule before releasing: ' + relative)
        entry = git(root, 'ls-tree', revision, '--', relative)
        if not entry.startswith('160000 commit '):
            raise ValueError('Release submodule is not a committed Git link: ' + relative)
        commit = entry.split()[2]
        target = safe_path(destination, relative)
        target.mkdir(parents=True, exist_ok=True)
        unpack(run(['git', '-C', original, 'archive', commit], capture=True), target)


def release_tag(revision, config):
    channel = config.get('channel')
    if channel is not None and not re.fullmatch(r'[a-z][a-z0-9-]*', channel):
        raise ValueError('Release channels must be lowercase names')
    return 'release-' + (channel + '-' if channel else '') + revision


def read_manifest(gh, repository, release):
    assets = [a for a in release['assets'] if a['name'] == 'release.json']
    if release['draft'] or not release.get('immutable') or len(assets) != 1:
        raise ValueError('A partial, draft or mutable release cannot be reused')
    asset = assets[0]
    data = gh.api(f'repos/{repository}/releases/assets/{asset["id"]}', binary=True)
    if 'sha256:' + hashlib.sha256(data).hexdigest() != asset.get('digest'):
        raise ValueError('Release manifest checksum mismatch')
    return json.loads(data)


def require_private_package(gh, repository, config, *, published=False):
    owner = repository.split('/')[0]
    prefix = 'ghcr.io/' + owner + '/'
    if not re.fullmatch(re.escape(prefix) + r'[a-z0-9][a-z0-9._-]*', config['image']):
        raise ValueError('The image must belong to the source repository owner')
    package = config['image'].removeprefix(prefix)
    record = gh.api(f'users/{owner}/packages/container/{package}', missing=not published)
    if record is not None and record['visibility'] != 'private':
        raise ValueError('Refusing to upload private application content to a public package')


def completed(gh, repository, revision, config):
    tag = release_tag(revision, config)
    release = gh.api(f'repos/{repository}/releases/tags/{tag}', missing=True)
    if release is None:
        return False
    ref = gh.api(f'repos/{repository}/git/ref/tags/{tag}')
    if ref['object']['type'] != 'commit' or ref['object']['sha'] != revision:
        raise ValueError('Release tag does not point to its declared source commit')
    manifest = read_manifest(gh, repository, release)
    qualification = manifest.get('qualification', {})
    if (manifest.get('repository') != repository or manifest.get('revision') != revision
            or manifest.get('channel') != config.get('channel')
            or qualification.get('policy') != POLICY
            or qualification.get('platform') != 'linux/amd64'
            or any(qualification.get(gate) is not True for gate in ('sourceChecks', 'runtimeSmoke', 'vulnerabilityScan'))
            or set(manifest.get('images', {})) != {'app'}
            or not re.fullmatch(re.escape(config['image']) + r'@sha256:[a-f0-9]{64}',
                                manifest.get('images', {}).get('app', ''))
            or not health_matches(manifest.get('health'), config)):
        raise ValueError('Existing release has a different identity or qualification policy')
    if config.get('evidence') and not any(a['name'] == 'evidence.tar.gz' and re.fullmatch(
            'sha256:[a-f0-9]{64}', a.get('digest', '')) for a in release['assets']):
        raise ValueError('Release evidence is incomplete')
    print(f'Already published: {release["html_url"]}', flush=True)
    return True


@contextmanager
def publication_lock(gh, repository, revision):
    """An atomic Git ref coordinates local and hosted publishers; it never expires."""
    prefix = f'repos/{repository}/git/'
    commit = gh.api(prefix + 'commits/' + revision)
    owner = gh.api(prefix + 'commits', 'POST', {
        'message': f'Publication claim {uuid.uuid4()} on {socket.gethostname()} pid {os.getpid()}',
        'tree': commit['tree']['sha'], 'parents': [revision]})['sha']
    try:
        gh.api(prefix + 'refs', 'POST', {'ref': 'refs/heads/release-publication-lock', 'sha': owner})
    except RuntimeError:
        raise RuntimeError('Publication lock unavailable. Inspect the release-publication-lock branch; '
                           'remove it only after confirming its publisher has stopped.') from None
    try:
        yield
    finally:
        record = gh.api(prefix + 'ref/heads/release-publication-lock', missing=True)
        if record and record['object']['sha'] == owner:
            gh.api(prefix + 'refs/heads/release-publication-lock', 'DELETE')


def toolchain(root, environment, project=None):
    expected = (root / '.nvmrc').read_text().strip().removeprefix('v')
    actual = run(['node', '--version'], env=environment, capture=True).decode().strip().removeprefix('v')
    if actual != expected:
        selected = Path.home() / '.nvm/versions/node' / ('v' + expected) / 'bin'
        if not (selected / 'node').is_file():
            raise ValueError(f'Install Node {expected} (see .nvmrc), then retry')
        environment['PATH'] = str(selected) + os.pathsep + environment['PATH']
    package = json.loads(((project or root) / 'package.json').read_text())
    if package.get('private') is not True:
        raise ValueError('Application packages must be private')
    manager, version = package['packageManager'].split('@')
    if manager not in ('npm', 'pnpm') or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Pin npm or pnpm to an exact version')
    tools = CACHE / 'tools'
    tools.mkdir(parents=True, exist_ok=True)
    # The registry's published integrity is the reference: the cached tarball is only a copy.
    dist = json.loads(run(['npm', 'view', manager + '@' + version, 'dist.tarball', 'dist.integrity', '--json'],
                          cwd=tools, env=environment, capture=True))
    algorithm, _, expected = dist['dist.integrity'].partition('-')
    if algorithm != 'sha512' or not dist['dist.tarball'].startswith('https://registry.npmjs.org/'):
        raise ValueError(f'{manager}@{version} must come from the npm registry with a sha512 integrity')
    tarball = verified_download(tools / f'{manager}-{version}.tgz', dist['dist.tarball'],
                                lambda data: base64.b64encode(hashlib.sha512(data).digest()).decode() == expected)
    # Reinstall from the verified tarball every time, so nothing in a restored install tree runs.
    install = tools / (manager + '-' + version)
    shutil.rmtree(install, ignore_errors=True)
    install.mkdir()
    (install / 'package.json').write_text(json.dumps({'private': True,
        'allowScripts': {manager + '@' + version: True}}) + '\n')
    run(['npm', 'install', '--prefix', install, '--offline', '--no-package-lock',
         '--no-audit', '--no-fund', tarball], cwd=install, env=environment)
    executable = install / 'node_modules/.bin' / manager
    # Nested package scripts must use the same pinned manager.
    environment['PATH'] = str(install / 'node_modules/.bin') + os.pathsep + environment['PATH']
    return [str(executable)]


def verified_download(path, url, verify):
    """A download cached at path and verified on every use: CI restores the cache from shared state, so a cached
    copy is trusted only while it still matches its reference."""
    if path.is_file() and verify(path.read_bytes()):
        return path
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    if not verify(data):
        raise ValueError('Download checksum mismatch: ' + url)
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(path.name + '.tmp')
    staged.write_bytes(data)
    staged.replace(path)
    return path


def pinned_executable(directory, url, checksum, member):
    """Extract a release archive's executable afresh from its verified, cached download."""
    directory = CACHE / 'tools' / directory
    archive = verified_download(directory / 'release.tar.gz', url, lambda data: hashlib.sha256(data).hexdigest() == checksum)
    executable = directory / member
    executable.unlink(missing_ok=True)
    with tarfile.open(archive) as release:
        executable.write_bytes(release.extractfile(release.getmember(member)).read())
    executable.chmod(0o755)
    return executable


def scan_source(root, environment):
    name, checksum = LEAKS[(platform.system(), platform.machine())]
    executable = pinned_executable(
        'gitleaks-8.30.1-' + name,
        f'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_{name}.tar.gz', checksum, 'gitleaks')
    run([executable, 'dir', root, '--redact=100', '--no-banner'], env=environment)


def lint_workflows(root, environment):
    name, checksum = ACTIONLINT[(platform.system(), platform.machine())]
    executable = pinned_executable(
        'actionlint-1.7.12-' + name,
        f'https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_{name}.tar.gz', checksum, 'actionlint')
    run(['shellcheck', '--version'], env=environment)
    workflows = sorted((root / '.github/workflows').glob('*.yml')) + sorted((root / '.github/workflows').glob('*.yaml'))
    run([executable, *workflows], cwd=root, env=environment)


HEAVY = re.compile(r'(?<![\w./-])(?:playwright|cypress|puppeteer|detox|maestro|xcodebuild|gradlew?)(?![\w.-])'
                   r'|--browser|\bbench|\bstress|test:(?:e2e|integration|browser)|--suite=integration'
                   r'|\bsimulators?\b|\bemulators?\b|expo run', re.IGNORECASE)
IMAGE_BUILD = re.compile(r'\b(?:docker|podman)\s+(?:buildx\s+)?(?:build|bake)\b|\bcontainer\s+build\b')
HOSTNAME = re.compile(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+')
# Health paths become Gatus URLs, and Gatus expands $ in its configuration.
REQUEST_PATH = re.compile(r"/(?!/)[A-Za-z0-9._~!&'()+,;=:@%/-]*")
# Markers become Gatus conditions '[BODY] == pat(*marker*)': Gatus expands $ in its configuration, matches
# patterns with * ? [ ] \ as syntax, and splits conditions at space-delimited operators.
MARKER = re.compile(r'(?! )(?!.* (?:[=!<>]=|[<>]) )[ -#%-)+->@-Z^-~]{1,128}(?<! )')
SCRIPT_DIRECTIVES = ('script-src', 'script-src-elem', 'script-src-attr')
SCRIPT_KEYWORDS = {"'self'", "'none'", "'wasm-unsafe-eval'", "'strict-dynamic'", "'report-sample'", 'blob:'}
SCRIPT_EXCEPTIONS = ('unsafe-eval', 'unsafe-inline')
ORIGIN = re.compile(r'https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?')
EVENTS_PATH = '/_/events'
TELEMETRY = ('googletagmanager', 'google-analytics', 'analytics.google.com', 'segment.io', 'segment.com',
             '@segment/', 'mixpanel', 'posthog', 'sentry.io', '@sentry/', 'hotjar', 'clarity.ms', 'datadoghq',
             '@datadog/', 'amplitude.com', '@amplitude/', 'amplitude-js', 'bugsnag', 'fullstory', 'logrocket',
             'measurementid', 'appcenter', 'flurry', 'instabug')
LOCKFILES = {'npm': 'package-lock.json', 'pnpm': 'pnpm-lock.yaml'}


def task_text(file, task, seen):
    """The body of one task in a tooling/tasks.mjs style table, following tasks[...] references."""
    if task in seen or not file.is_file():
        return ''
    seen.add(task)
    found = re.search(rf'^  (?:"{re.escape(task)}"|{re.escape(task)}): .*?(?=^  \S|\Z)', file.read_text(), re.M | re.S)
    body = found.group(0) if found else ''
    refs = re.findall(r'tasks\["([\w:.-]+)"\]|tasks\.(\w+)\(', body)
    return ' '.join([body, *(task_text(file, a or b, seen) for a, b in refs)])


def script_text(project, scripts, name, seen):
    """A script's command text including package scripts and task tables it delegates to."""
    if name in seen or name not in scripts:
        return ''
    seen.add(name)
    text = scripts[name]
    parts = [text]
    parts += [script_text(project, scripts, ref, seen) for ref in re.findall(r'\b(?:npm|pnpm)\s+(?:run\s+)?([\w:.-]+)', text)]
    for path, task in re.findall(r'(\S+\.mjs)\s+([\w:.-]+)', text):
        parts.append(task_text(project / path, task, set()))
    return ' '.join(parts)


def conform_scripts(project, config):
    scripts = json.loads((project / 'package.json').read_text()).get('scripts', {})
    issues = [f'Missing package script: {name}' for name in ('check', 'build', 'check:all') if name not in scripts]
    for name in dict.fromkeys(['check', config.get('check', 'check'), *config.get('checks', [])]):
        found = HEAVY.search(script_text(project, scripts, name, set()))
        if found:
            issues.append(f'Script {name} runs heavy work ({found.group(0)}); move it to check:all')
    if 'tools/heavy' not in scripts.get('check:all', ''):
        issues.append('Script check:all must run through the monorepo tools/heavy admission wrapper')
    # Each heavy entrypoint admits itself; nested admissions inside check:all pass straight through.
    for name, command in scripts.items():
        if name != 'check:all' and (HEAVY.search(name) or HEAVY.search(command) or IMAGE_BUILD.search(command)) \
                and 'tools/heavy' not in command:
            issues.append(f'Script {name} is a heavy entrypoint; run it through the monorepo tools/heavy admission wrapper')
    return issues


def conform_package(root, project, config):
    issues = []
    if not (root / '.nvmrc').is_file():
        issues.append('Missing .nvmrc')
    package = json.loads((project / 'package.json').read_text())
    manager = re.fullmatch(r'(npm|pnpm)@\d+\.\d+\.\d+', package.get('packageManager', ''))
    if not manager:
        return issues + ['Pin exactly one package manager (npm or pnpm) to an exact version in packageManager']
    manager, major = manager.group(1), int(package['packageManager'].split('@')[1].split('.')[0])
    if manager == 'pnpm' and major < 11:
        issues.append('Pin pnpm 11 or newer; automatic security fixes need pnpm audit --fix=update')
    lockfiles = [name for name in ('package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb')
                 if (project / name).exists()]
    if lockfiles != [LOCKFILES[manager]]:
        issues.append(f'Expected only {LOCKFILES[manager]} for {manager}, found {lockfiles}')
    for found in [project / 'package.json', *project.glob('*/package.json'), *project.glob('packages/*/package.json'),
                  *project.glob('apps/*/package.json')]:
        if json.loads(found.read_text()).get('private') is not True:
            issues.append(f'{found.relative_to(root)} must declare private: true')
    # One uniform cooldown: npm counts days, pnpm minutes. Security fixes resolve under the same rule.
    name, pattern = {'npm': ('.npmrc', rf'^min-release-age\s*=\s*{COOLDOWN_DAYS}\s*$'),
                     'pnpm': ('pnpm-workspace.yaml', rf'^minimumReleaseAge:\s*{COOLDOWN_DAYS * 1440}\s*$')}[manager]
    if not any(re.search(pattern, (directory / name).read_text(), re.M)
               for directory in (project, root) if (directory / name).is_file()):
        issues.append(f'Configure the uniform {COOLDOWN_DAYS}-day release-age cooldown '
                      f'(min-release-age={COOLDOWN_DAYS} in .npmrc for npm, minimumReleaseAge: {COOLDOWN_DAYS * 1440} '
                      'in pnpm-workspace.yaml for pnpm)')
    return issues


def conform_release(config):
    issues = []
    command = config.get('audit')
    if (not isinstance(command, list) or not command
            or not all(isinstance(word, str) and word for word in command)
            or not any('audit' in word for word in command)):
        issues.append('.release/config.json audit must name the dependency audit command')
    if not isinstance(config.get('browserEvents', False), bool):
        issues.append('.release/config.json browserEvents must be a boolean')
    return issues + conform_health(config)


def conform_health(config):
    """One declaration serves qualification, the post-deploy gate and continuous monitoring."""
    issues = ['.release/config.json smoke is replaced by health'] if 'smoke' in config else []
    entries = config.get('health')
    if not isinstance(entries, list) or not entries:
        return issues + ['.release/config.json health must list at least one {host, path, file, marker} check']
    seen = set()
    for entry in entries:
        if (not isinstance(entry, dict) or not {'host', 'path', 'file', 'marker'} <= set(entry) <= {'host', 'path', 'file', 'marker', 'sso'}
                or not all(isinstance(entry[key], str) for key in ('host', 'path', 'file', 'marker'))):
            issues.append('Each health check names host, path, file and marker strings, and optionally sso')
            continue
        name = f'health {entry["host"]}{entry["path"]}'
        if not HOSTNAME.fullmatch(entry['host']):
            issues.append(f'{name}: host must be a lowercase DNS name')
        if not REQUEST_PATH.fullmatch(entry['path']):
            issues.append(f'{name}: path must be an application-relative path without query or fragment')
        if not entry['file'] or entry['file'].startswith('/') or '..' in entry['file'].split('/'):
            issues.append(f'{name}: file must be relative to the static output')
        if not MARKER.fullmatch(entry['marker']):
            issues.append(f'{name}: marker must be 1-128 printable ASCII characters without edge spaces, '
                          '$ * ? [ ] \\ or a space-delimited comparison operator')
        if entry.get('sso', True) is not True:
            issues.append(f'{name}: sso may only be true')
        if (entry['host'], entry['path']) in seen:
            issues.append(f'{name}: duplicate check')
        seen.add((entry['host'], entry['path']))
    return issues


def health_manifest(config, record):
    """Manifest entries pin each checked response to the verified file's exact digest."""
    entries = []
    for entry in config['health']:
        relative = 'site/' + entry['file']
        if relative not in record['files']:
            raise ValueError('Health check file is not part of the verified output: ' + entry['file'])
        entries.append({'host': entry['host'], 'path': entry['path'], 'sha256': record['files'][relative],
                        'marker': entry['marker'], **({'sso': True} if entry.get('sso') else {})})
    return entries


def health_matches(entries, config):
    expected = [(e['host'], e['path'], e['marker'], e.get('sso', False)) for e in config.get('health', [])]
    return (isinstance(entries, list) and bool(entries)
            and all(isinstance(e, dict) and re.fullmatch('[a-f0-9]{64}', str(e.get('sha256'))) for e in entries)
            and [(e.get('host'), e.get('path'), e.get('marker'), e.get('sso', False)) for e in entries] == expected)


def deploy_command(ref, sha256):
    return DEPLOY.replace('{ref}', ref).replace('{sha256}', sha256)


def deploy_pin(text):
    ref = re.search(r'^REF = "([0-9a-f]{40})"$', text, re.M)
    sha256 = re.search(r'^SHA256 = "([0-9a-f]{64})"$', text, re.M)
    return (ref.group(1), sha256.group(1)) if ref and sha256 else None


def repin(text, ref, sha256):
    text = re.sub(r'^REF = "[0-9a-f]{40}"$', f'REF = "{ref}"', text, count=1, flags=re.M)
    return re.sub(r'^SHA256 = "[0-9a-f]{64}"$', f'SHA256 = "{sha256}"', text, count=1, flags=re.M)


def publisher_manifest(ref, source):
    """publisher.json: the publisher digest and the committed wiring a GITHUB_TOKEN refresh leaves unchanged."""
    return json.dumps({'ref': ref, 'sha256': hashlib.sha256(source).hexdigest(),
                       'template': hashlib.sha256(TEMPLATE.encode()).hexdigest(),
                       'deploy': hashlib.sha256(DEPLOY.encode()).hexdigest()}) + '\n'


def committed_text(root, revision, path):
    if not git(root, 'ls-tree', revision, '--', path):
        return None
    return run(['git', '-C', root, 'show', f'{revision}:{path}'], capture=True).decode()


def conform_repository(root, revision):
    """Committed release wiring: the static CI template, the single publisher pin and local-only heavy work."""
    issues = []
    if committed_text(root, revision, WORKFLOW) != TEMPLATE:
        issues.append(f'{WORKFLOW} must equal the publisher template (python3 .release/deploy.py template)')
    for path in git(root, 'ls-tree', '--name-only', revision, '.github/workflows/').splitlines():
        if path == WORKFLOW or not path.endswith(('.yml', '.yaml')):
            continue
        text = committed_text(root, revision, path).lower()
        if LEGACY_CALLER in text:
            issues.append(f'{path} calls the retired shared release workflow')
        if re.search(r'^\s*(?:schedule:|-\s*cron:)', text, re.M) and (HEAVY.search(text) or 'check:all' in text):
            issues.append(f'{Path(path).name} schedules heavy work; keep it local')
    command = committed_text(root, revision, '.release/deploy.py') or ''
    pin = deploy_pin(command)
    if pin is None or command != deploy_command(*pin):
        issues.append('.release/deploy.py must be the publisher deploy command with only its REF and SHA256 pin')
    return issues


def declarations(config, key, valid):
    value = config.get(key, {})
    if not isinstance(value, dict) or not all(isinstance(reason, str) and reason.strip() for reason in value.values()):
        return {}, [f'.release/config.json {key} must map each source to the reason it is needed']
    return value, [f'.release/config.json {key} cannot declare {source}' for source in value if not valid(source)]


def conform_nginx(root, config):
    # User-configured HTTPS APIs are an explicit capability; other origins stay named.
    text = (root / 'nginx.conf').read_text()
    # Policies may live in a nginx map value, so match quoted strings rather than add_header lines.
    policies = re.findall(r'"([^"]*(?:script-src|connect-src)[^"]*)"', text) if 'Content-Security-Policy' in text else []
    directives = [{(d.split() or [''])[0]: d.split()[1:] for d in policy.split(';')} for policy in policies]
    custom_api_endpoints = config.get('customApiEndpoints', False)
    issues = [] if isinstance(custom_api_endpoints, bool) else ['.release/config.json customApiEndpoints must be a boolean']
    origins, found = declarations(config, 'scriptOrigins', ORIGIN.fullmatch)
    exceptions, more = declarations(config, 'scriptExceptions', lambda source: source in SCRIPT_EXCEPTIONS)
    issues += found + more
    used = set()
    for name in ('connect-src', 'script-src'):
        if not any(name in policy for policy in directives):
            issues.append(f'nginx.conf needs a Content-Security-Policy with {name}')
        for policy in directives:
            issues += [f'nginx.conf {name} allows the whole scheme or wildcard {source}' for source in policy.get(name, [])
                       if not source.startswith("'") and source not in ('data:', 'blob:')
                       and not (name == 'connect-src' and source == 'https:' and custom_api_endpoints is True)
                       and (source.endswith(':') or re.sub(r'^[a-z]+://', '', source) == '*')]
    for policy in directives:
        # Third-party code and string evaluation are exceptions, each carrying its reason.
        for name in SCRIPT_DIRECTIVES:
            for source in policy.get(name, []):
                bare = source.strip("'")
                if source in SCRIPT_KEYWORDS or re.fullmatch(r"'(?:nonce|sha256|sha384|sha512)-[^']+'", source):
                    continue
                used.add(bare)
                if bare in SCRIPT_EXCEPTIONS:
                    if bare not in exceptions:
                        issues.append(f'nginx.conf {name} {source} needs a scriptExceptions reason')
                elif ORIGIN.fullmatch(source):
                    if source not in origins:
                        issues.append(f'nginx.conf {name} {source} needs a scriptOrigins reason')
                elif source.endswith(':') or '*' in source:
                    issues.append(f'nginx.conf {name} allows the whole scheme or wildcard {source}')
                else:
                    issues.append(f'nginx.conf {name} cannot allow {source}')
        if policy.get('object-src') != ["'none'"]:
            issues.append("nginx.conf Content-Security-Policy needs object-src 'none'")
        if not policy.get('base-uri') or not set(policy['base-uri']) <= {"'self'", "'none'"}:
            issues.append("nginx.conf Content-Security-Policy needs base-uri 'self' or 'none'")
        ancestors = policy.get('frame-ancestors')
        if not ancestors or not all(source in ("'self'", "'none'") or ORIGIN.fullmatch(source) for source in ancestors) \
                or ("'none'" in ancestors and len(ancestors) > 1):
            issues.append("nginx.conf Content-Security-Policy needs frame-ancestors of 'none', 'self' or named https origins")
    issues += [f'.release/config.json declares unused script source {source}'
               for source in [*origins, *exceptions] if source not in used]
    return issues


class IndexPage(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.external = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        reference = attrs.get('src') if tag == 'script' else attrs.get('href') if tag == 'link' and 'stylesheet' in (attrs.get('rel') or '') else None
        if reference and re.match(r'(?:https?:)?//', reference):
            self.external.append(reference)


def conform_bundle(root, config):
    """Standards only the built output can show: no telemetry or external assets, live health markers."""
    dist, root = safe_path(root, config['dist']), root.resolve()
    issues, reports_events = [], False
    for path in sorted(dist.rglob('*')):
        if path.suffix not in ('.html', '.js', '.mjs', '.css') or not path.is_file():
            continue
        text = path.read_text(errors='ignore')
        lowered = text.lower()
        reports_events = reports_events or (path.suffix in ('.js', '.mjs') and EVENTS_PATH in text)
        issues += [f'{path.relative_to(root)} contains telemetry marker {word}' for word in TELEMETRY if word in lowered]
        if path.name == 'index.html':
            page = IndexPage()
            page.feed(text)
            issues += [f'{path.relative_to(root)} loads external {reference}' for reference in page.external]
    for entry in config['health']:
        path = safe_path(dist, entry['file'])
        if not path.is_file() or entry['marker'].encode() not in path.read_bytes():
            issues.append(f'{config["dist"]}/{entry["file"]} lacks the health marker for {entry["host"]}{entry["path"]}')
    if config.get('browserEvents') and not reports_events:
        issues.append(f'browserEvents requires the vendored client that reports to {EVENTS_PATH}')
    return issues


def conform_static(root, config):
    """Standards checked from committed source alone, before any install or build."""
    project = safe_path(root, config['workingDirectory']) if config.get('workingDirectory') else root
    return [*conform_scripts(project, config), *conform_package(root, project, config), *conform_release(config),
            *conform_nginx(root, config)]


def require(issues):
    if issues:
        raise ValueError('Nonconforming application:\n' + '\n'.join(sorted(set(issues))))


def audit(gh, root, revision, config):
    """Audit the committed lockfile, static standards and publisher adoption even when this revision already has a release."""
    adoptable = adoptable_publisher(gh, root, revision)
    if adoptable:
        print(f'Publisher {adoptable[0][:12]} awaits the weekly refresh.', flush=True)
    with tempfile.TemporaryDirectory(prefix='app-audit-') as temporary:
        source = Path(temporary)
        environment = {**os.environ, **config.get('environment', {}), **SAFE_ENV,
                       'GH_CONFIG_DIR': str(source / 'no-github-credentials')}
        for key in CREDENTIALS:
            environment.pop(key, None)
        archive_source(root, revision, source, config.get('submodules', []), config.get('sourceInputs', []))
        require(conform_repository(root, revision) + conform_static(source, config))
        project = safe_path(source, config['workingDirectory']) if config.get('workingDirectory') else source
        manager = toolchain(source, environment, project)
        run([*manager, *config['audit']], cwd=project, env=environment, timeout=180)


def verify(root, revision, repository, config, output, *, local=True):
    environment = {**os.environ, **config.get('environment', {}), **SAFE_ENV, 'SOURCE_REVISION': revision}
    # Verification never receives publisher credentials, including through gh's keychain.
    for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN'):
        environment.pop(key, None)
    environment['GH_CONFIG_DIR'] = str(output / 'no-github-credentials')
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='app-source-') as temporary:
        source = Path(temporary)
        archive_source(root, revision, source, config.get('submodules', []), config.get('sourceInputs', []))
        require(conform_repository(root, revision) + conform_static(source, config))
        scan_source(source, environment)
        if config.get('workflowLint'):
            lint_workflows(source, environment)
        for name, relative in config.get('cacheEnv', {}).items() if local else []:
            environment[name] = str(safe_path(root, relative))
        # Vite reads the private local build inputs, but only after committed-source scanning.
        if local and config.get('localEnv'):
            original = safe_path(root, config['localEnv'])
            if original.is_file():
                shutil.copyfile(original, safe_path(source, config['localEnv']))
                safe_path(source, config['localEnv']).chmod(0o600)
        for name in config.get('variables', []):
            if name not in environment:
                value = run(['gh', 'variable', 'get', name, '--repo', repository], capture=True).decode().strip()
                if value:
                    environment[name] = value
        project = safe_path(source, config['workingDirectory']) if config.get('workingDirectory') else source
        manager = toolchain(source, environment, project)
        install = ['ci'] if Path(manager[0]).name == 'npm' else ['install', '--frozen-lockfile']
        run([*manager, *install], cwd=project, env=environment)
        for command in [config.get('check', 'check'), *config.get('checks', [])]:
            run([*manager, 'run', command], cwd=project, env=environment, timeout=600)
        run([*manager, *config['audit']], cwd=project, env=environment, timeout=180)
        for command in config.get('beforeBuild', []):
            run([*manager, *command], cwd=project, env=environment)
        run([*manager, 'run', config.get('build', 'build')], cwd=project, env=environment)
        for relative in config['required']:
            if not safe_path(source, relative).is_file() or not safe_path(source, relative).stat().st_size:
                raise ValueError('Required build output missing: ' + relative)
        require(conform_bundle(source, config))
        shutil.copytree(safe_path(source, config['dist']), output / 'site')
        shutil.copyfile(source / 'nginx.conf', output / 'nginx.conf')
        for relative in config.get('evidence', []):
            target = safe_path(output / 'evidence', relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(safe_path(source, relative), target)
    files = {str(path.relative_to(output)): digest(path) for path in output.rglob('*') if path.is_file()}
    (output / 'verified.json').write_text(json.dumps({'repository': repository, 'revision': revision,
        'config': config, 'policy': POLICY, 'files': files}) + '\n')


# Executed on an existing native amd64 host. It reads only that host's registry identity;
# neither the local GitHub session nor provider build secrets are transmitted.
ACCEPT = r'''
import hashlib,json,os,pathlib,platform,signal,subprocess,sys,tempfile,time,urllib.request,uuid
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
client=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
image,checks=sys.argv[1],json.loads(sys.argv[2])
assert platform.machine()=='x86_64', 'Native amd64 qualification is required'
for sig in (signal.SIGTERM,signal.SIGHUP): signal.signal(sig,lambda *_: sys.exit(143))
name='app-acceptance-'+uuid.uuid4().hex
with tempfile.TemporaryDirectory(prefix='app-acceptance-') as private:
 env={**os.environ,'DOCKER_CONFIG':private}
 def run(args,capture=False,data=None):
  return subprocess.run(args,check=True,env=env,input=data,timeout=120,stdout=subprocess.PIPE if capture else None).stdout
 existed=subprocess.run(['docker','image','inspect',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
 try:
  if pathlib.Path('/etc/servers-controller/secrets.json').is_file():
   token=json.loads(pathlib.Path('/etc/servers-controller/secrets.json').read_text())['registry_read_token']
   run(['docker','login','ghcr.io','--username','xmanatee','--password-stdin'],data=(token+'\n').encode(),capture=True)
  else:
   env=os.environ.copy()
  run(['docker','pull','--platform','linux/amd64',image])
  run(['docker','run','--platform','linux/amd64','--name',name,'--detach','--publish','127.0.0.1::80',image],capture=True)
  port=run(['docker','port',name,'80/tcp'],True).decode().strip().rsplit(':',1)[1]
  for check in checks:
   request=urllib.request.Request('http://127.0.0.1:'+port+check['path'],headers={'Host':check.get('host','localhost')})
   for attempt in range(30):
    try:
     with client.open(request,timeout=3) as response: data=response.read()
     break
    except urllib.error.HTTPError as error:
     error.close()
     raise
    except OSError:
     if attempt==29: raise
     time.sleep(1)
   assert hashlib.sha256(data).hexdigest()==check['sha256'], 'Runtime response differs from verified build: '+check['path']
  run(['docker','exec',name,'nginx','-t'])
 finally:
  subprocess.run(['docker','rm','--force',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  if not existed:
   subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
'''


def qualify(image, checks, remote):
    checks = json.dumps(checks)
    if remote:
        if not re.fullmatch(r'[a-zA-Z0-9_.@:-]+', remote):
            raise ValueError('Invalid native qualification host')
        command = shlex.join(['sudo', '-n', 'python3', '-c', ACCEPT, image, checks])
        run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', remote, command])
    else:
        architecture = run(['docker', 'version', '--format', '{{.Server.Arch}}'], capture=True).decode().strip()
        if architecture != 'amd64':
            raise ValueError('Set RELEASE_QUALIFIER to a native amd64 host; CPU emulation is not used')
        run(['python3', '-c', ACCEPT, image, checks])


def should_promote(revision, current_main):
    return revision == current_main


def validate_artifact(repository, revision, config, output):
    record = json.loads((output / 'verified.json').read_text())
    if (record['repository'], record['revision'], record['config'], record['policy']) != (
            repository, revision, config, POLICY):
        raise ValueError('Verified artifact identity mismatch')
    for relative, checksum in record['files'].items():
        if digest(safe_path(output, relative)) != checksum:
            raise ValueError('Verified artifact was modified: ' + relative)
    if {str(p.relative_to(output)) for p in output.rglob('*')
            if p.is_file() and p != output / 'verified.json'} != set(record['files']):
        raise ValueError('Verified artifact file inventory changed')
    return record


def image_context(output, context, immutable_directories=()):
    """Package independent static directories with deterministic layer metadata."""
    if any(not re.fullmatch(r'[a-zA-Z0-9_-][a-zA-Z0-9._-]*', name)
           or not (output / 'site' / name).is_dir() for name in immutable_directories):
        raise ValueError('Immutable directories must name existing top-level static output directories')
    context.mkdir()
    shutil.copyfile(output / 'nginx.conf', context / 'nginx.conf')
    lines = [f'FROM {BASE}', 'COPY nginx.conf /etc/nginx/nginx.conf']
    entries = sorted((output / 'site').iterdir())
    groups = [[path] for path in entries if path.is_dir()]
    files = [path for path in entries if not path.is_dir()]
    if files:
        groups.append(files)
    for index, group in enumerate(groups):
        layer = context / 'layers' / str(index)
        destination = layer / 'usr/share/nginx/html'
        destination.mkdir(parents=True)
        for path in group:
            target = destination / path.name
            if path.is_dir():
                shutil.copytree(path, target)
            else:
                shutil.copy2(path, target)
        # Include deterministic parent directories; otherwise COPY invents timestamps.
        for path in [layer, *layer.rglob('*')]:
            path.chmod(0o755 if path.is_dir() else 0o644)
            # Mutable files retain their mtime for nginx ETag/Last-Modified checks.
            if path.is_dir() or group[0].name in immutable_directories:
                os.utime(path, (0, 0))
        lines.append(f'COPY --link layers/{index}/ /')
    lines.append('HEALTHCHECK --interval=15s --timeout=5s --retries=3 CMD wget -q --spider http://127.0.0.1/')
    return '\n'.join(lines) + '\n'


def refresh_scanner_database(scanner, environment):
    # Trivy tries its next repository only after a registry's temporary error, not after a failed download.
    for attempt in range(1, 4):
        for repository in TRIVY_DATABASES:
            try:
                return run([*scanner, '--download-db-only', '--db-repository', repository, '--no-progress',
                            '--timeout', '5m'], env=environment)
            except RuntimeError:
                pass
        time.sleep(attempt * 30)
    raise RuntimeError('No repository served the vulnerability database. This is not a security finding; rerun the release.')


def scan_image(image, private, environment):
    # Export the selected digest once; the scanner gets no registry or Docker socket access.
    archive = private / 'image.tar'
    run(['docker', 'image', 'save', '--output', archive, image], env=environment)
    archive.chmod(0o644)
    cache = CACHE / 'trivy'
    cache.mkdir(parents=True, exist_ok=True)
    cache.chmod(0o777)
    native = run(['docker', 'version', '--format', '{{.Server.Arch}}'], env=environment, capture=True).decode().strip()
    if native not in ('amd64', 'arm64'):
        raise ValueError('A native amd64 or arm64 Docker worker is required for scanning')
    container = ['docker', 'run', '--rm', '--platform', 'linux/' + native, '--user', '65532:65532', '--cap-drop', 'ALL',
                 '--security-opt', 'no-new-privileges', '--mount', f'type=bind,src={cache},dst=/cache']
    scanner = ['image', '--cache-dir', '/cache', '--disable-telemetry', '--skip-version-check']
    # Trivy's filesystem cache is process-exclusive, including across repositories.
    with (CACHE / 'trivy.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        refresh_scanner_database([*container, TRIVY, *scanner], environment)
        run([*container, '--mount', f'type=bind,src={archive},dst=/scan/image.tar,readonly', TRIVY, *scanner,
             '--skip-db-update', '--input', '/scan/image.tar', '--platform', 'linux/amd64', '--scanners', 'vuln',
             '--severity', 'HIGH,CRITICAL', '--ignore-unfixed', '--exit-code', '1', '--timeout', '15m'], env=environment)


def publish(gh, repository, revision, config, output, qualifier):
    record = validate_artifact(repository, revision, config, output)
    with publication_lock(gh, repository, revision):
        if completed(gh, repository, revision, config):
            return
        require_private_package(gh, repository, config)
        with tempfile.TemporaryDirectory(prefix='app-publisher-') as private:
            private = Path(private)
            environment = {**os.environ, **SAFE_ENV, 'DOCKER_CONFIG': str(private / 'docker')}
            # Preserve the user's daemon/context selection, never their saved credentials.
            original = Path(os.environ.get('DOCKER_CONFIG', Path.home() / '.docker')) / 'config.json'
            docker_config = json.loads(original.read_text()) if original.exists() else {}
            (private / 'docker').mkdir(mode=0o700)
            (private / 'docker/config.json').write_text(json.dumps({
                k: v for k, v in docker_config.items() if k in ('currentContext', 'cliPluginsExtraDirs')}))
            if 'currentContext' in docker_config and (original.parent / 'contexts').exists():
                (private / 'docker/contexts').symlink_to(original.parent / 'contexts', target_is_directory=True)
            if (original.parent / 'cli-plugins').exists():
                (private / 'docker/cli-plugins').symlink_to(original.parent / 'cli-plugins', target_is_directory=True)
            environment['BUILDX_CONFIG'] = str(original.parent / 'buildx')
            run(['docker', 'login', 'ghcr.io', '--username', repository.split('/')[0], '--password-stdin'],
                env=environment, data=(gh.token + '\n').encode(), capture=True)
            dockerfile = private / 'Dockerfile'
            context = private / 'context'
            dockerfile.write_text(image_context(output, context, config.get('immutableDirectories', [])))
            tag = config['image'] + ':sha-' + revision
            metadata = private / 'build.json'
            run(['docker', 'buildx', 'build', '--platform', 'linux/amd64', '--push', '--provenance=false',
                 '--tag', tag, '--metadata-file', metadata, '--file', dockerfile, '--label',
                 'org.opencontainers.image.source=https://github.com/' + repository,
                 '--label', 'org.opencontainers.image.revision=' + revision, context], env=environment)
            image = config['image'] + '@' + json.loads(metadata.read_text())['containerimage.digest']
            require_private_package(gh, repository, config, published=True)
            # The native CI worker uses its temporary publisher config for the pull.
            if not qualifier:
                os.environ['DOCKER_CONFIG'] = environment['DOCKER_CONFIG']
            require(conform_health(config))
            health = health_manifest(config, record)
            qualify(image, [{'host': e['host'], 'path': e['path'], 'sha256': e['sha256']} for e in health], qualifier)
            scan_image(image, private, environment)
            if config.get('channel') and revision != gh.api(f'repos/{repository}/commits/main')['sha']:
                raise ValueError('Main advanced during qualification; release its newer revision instead')
            manifest = {'repository': repository, 'revision': revision, 'images': {'app': image},
                        'qualification': {'policy': POLICY, 'platform': 'linux/amd64',
                                          'sourceChecks': True, 'runtimeSmoke': True, 'vulnerabilityScan': True},
                        'health': health}
            if config.get('channel'):
                manifest['channel'] = config['channel']
            manifest_path = private / 'release.json'
            manifest_path.write_text(json.dumps(manifest) + '\n')
            assets = [str(manifest_path)]
            if (output / 'evidence').exists():
                evidence = private / 'evidence.tar.gz'
                with tarfile.open(evidence, 'w:gz') as archive:
                    archive.add(output / 'evidence', arcname='evidence')
                assets.append(str(evidence))
            gh_env = {**environment, 'GH_TOKEN': gh.token}
            tag = release_tag(revision, config)
            reference = gh.api(f'repos/{repository}/git/ref/tags/{tag}', missing=True)
            if reference is None:
                gh.api(f'repos/{repository}/git/refs', 'POST', {'ref': 'refs/tags/' + tag, 'sha': revision})
            elif reference['object']['type'] != 'commit' or reference['object']['sha'] != revision:
                raise ValueError('Release tag already identifies different source')
            run(['gh', 'release', 'create', tag, *assets, '--repo', repository,
                 '--verify-tag', '--title', 'Release ' + revision[:12], '--notes',
                 'Qualified private application image. Deployment follows the existing Ansible poller.',
                 '--draft', '--latest=false'], env=gh_env)
            latest = gh.api(f'repos/{repository}/commits/main')['sha']
            promote = should_promote(revision, latest)
            if config.get('channel') and not promote:
                raise ValueError('Main advanced before publication; inspect the draft before retrying')
            run(['gh', 'release', 'edit', tag, '--repo', repository, '--draft=false',
                 '--latest=' + str(promote and not config.get('channel')).lower()], env=gh_env)
            if not completed(gh, repository, revision, config):
                raise ValueError('Published release could not be verified')
            print('Published for Ansible polling.' if promote else 'Published; newer main exists, latest preserved.')


def admit(root):
    """Queue local heavy work behind the monorepo's single admission lock; hosted runners are dedicated."""
    if os.environ.get('GITHUB_ACTIONS') or os.environ.get('HEAVY_ADMITTED'):
        return
    heavy = next((parent / 'tools/heavy' for parent in root.parents if (parent / 'tools/heavy').is_file()), None)
    if heavy is None:
        raise ValueError('Local releases run through the monorepo tools/heavy admission; none was found above ' + str(root))
    os.execv(sys.executable, [sys.executable, str(heavy), '--budget', '7200', '--',
                              sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])


def commit_as_bot(root, paths, message):
    run(['git', '-C', root, '-c', 'user.name=' + BOT[0], '-c', 'user.email=' + BOT[1], '-c', 'commit.gpgsign=false',
         'commit', '--no-verify', '--quiet', '--message', message, '--', *paths], capture=True)
    return git(root, 'rev-parse', 'HEAD')


def push_main(root, repository, token, revision):
    # Without --force the remote accepts only a fast-forward of the main this run started from.
    header = 'AUTHORIZATION: basic ' + base64.b64encode(f'x-access-token:{token}'.encode()).decode()
    environment = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_COUNT': '1',
                   'GIT_CONFIG_KEY_0': 'http.https://github.com/.extraheader', 'GIT_CONFIG_VALUE_0': header}
    run(['git', '-C', root, 'push', f'https://github.com/{repository}.git', f'{revision}:refs/heads/main'],
        env=environment, capture=True)


def dispatch(gh, repository, workflow):
    # Pushes made with GITHUB_TOKEN start no workflow; a dispatch is the permitted trigger.
    gh.api(f'repos/{repository}/actions/workflows/{workflow}/dispatches', 'POST', {'ref': 'main'})


def current_main(gh, root, revision, repository):
    if git(root, 'status', '--porcelain'):
        raise ValueError('Automatic commits start from a clean checkout')
    if revision != gh.api(f'repos/{repository}/commits/main')['sha']:
        raise ValueError('Automatic commits apply only to the current main')


def output(name, value):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write(f'{name}={value}\n')


def changed_paths(root):
    return set(git(root, 'diff', '--name-only').splitlines()) | set(
        git(root, 'ls-files', '--others', '--exclude-standard').splitlines())


def lockfile_path(root, config):
    """The project directory and the committed manager's lockfile, relative to the repository root."""
    project = safe_path(root, config['workingDirectory']) if config.get('workingDirectory') else root.resolve()
    manager = re.fullmatch(r'(npm|pnpm)@\d+\.\d+\.\d+', json.loads((project / 'package.json').read_text()).get('packageManager', ''))
    if not manager:
        raise ValueError('Pin npm or pnpm to an exact version')
    return project, manager.group(1), str((project / LOCKFILES[manager.group(1)]).relative_to(root.resolve()))


def fix(gh, root, revision, repository, config, artifact):
    """Resolve a lockfile-only security fix and commit it locally, before any dependency code runs.

    This runs without write credentials. The commit is qualified by the separate verify step, and only
    apply-fix, which installs and builds nothing, may push the resulting tree.
    """
    current_main(gh, root, revision, repository)
    project, name, lockfile = lockfile_path(root, config)
    environment = {**os.environ, **config.get('environment', {}), **SAFE_ENV, 'npm_config_ignore_scripts': 'true',
                   'GH_CONFIG_DIR': str(CACHE / 'no-github-credentials')}
    for key in CREDENTIALS:
        environment.pop(key, None)
    manager = toolchain(root, environment, project)
    try:
        run([*manager, *config['audit']], cwd=project, env=environment, timeout=180)
    except RuntimeError:
        pass
    else:
        raise ValueError('The committed dependencies pass their audit; correct the standards the audit reported')
    # The release-age cooldown in the committed manager configuration governs which versions resolve.
    run([*manager, *(['audit', 'fix', '--package-lock-only'] if name == 'npm' else ['audit', '--fix=update'])],
        cwd=project, env=environment, timeout=600)
    changed = changed_paths(root)
    if changed - {lockfile}:
        raise ValueError('The security fix changes more than the lockfile; make a reviewed change: '
                         + ', '.join(sorted(changed - {lockfile})))
    if not changed:
        raise ValueError('No lockfile-only fix resolves the audit; make a reviewed dependency change')
    try:
        run([*manager, *config['audit']], cwd=project, env=environment, timeout=180)
    except RuntimeError:
        raise ValueError('The lockfile-only fix does not satisfy the audit; make a reviewed dependency change') from None
    fixed = commit_as_bot(root, [lockfile], 'Apply lockfile-only security fixes')
    artifact.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(root / lockfile, artifact / Path(lockfile).name)
    tree = git(root, 'rev-parse', fixed + '^{tree}')
    output('tree', tree)
    print(f'Committed {fixed[:12]} (tree {tree[:12]}) locally; qualify it before apply-fix pushes it.', flush=True)


def apply_fix(gh, root, revision, repository, config, artifact, tree):
    """Fast-forward main to the qualified lockfile-only fix; nothing is installed or built here."""
    if not re.fullmatch('[0-9a-f]{40}', tree or ''):
        raise ValueError('apply-fix needs the qualified fix tree')
    current_main(gh, root, revision, repository)
    _, _, lockfile = lockfile_path(root, config)
    files = list(artifact.iterdir())
    if [path.name for path in files] != [Path(lockfile).name] or files[0].is_symlink() or not files[0].is_file():
        raise ValueError(f'The fix artifact must hold only {Path(lockfile).name}')
    shutil.copyfile(files[0], root / lockfile)
    if changed_paths(root) != {lockfile}:
        raise ValueError('The fix artifact does not change exactly ' + lockfile)
    fixed = commit_as_bot(root, [lockfile], 'Apply lockfile-only security fixes')
    if git(root, 'rev-parse', fixed + '^{tree}') != tree:
        raise ValueError('The fix artifact differs from the qualified fix')
    push_main(root, repository, gh.token, fixed)
    dispatch(gh, repository, Path(WORKFLOW).name)
    print(f'Pushed {fixed[:12]} to main and requested its release.', flush=True)


def latest_publisher(gh):
    """The newest immutable publisher release and the digests its publisher.json vouches for."""
    for release in gh.api(f'repos/{PUBLISHER}/releases?per_page=30'):
        tag = release['tag_name']
        if release['draft'] or not release.get('immutable') or not re.fullmatch(r'publisher-[0-9a-f]{40}', tag):
            continue
        ref = tag.removeprefix('publisher-')
        target = gh.api(f'repos/{PUBLISHER}/git/ref/tags/{tag}')['object']
        if target['type'] != 'commit' or target['sha'] != ref:
            raise ValueError(f'{tag} does not point to its declared publisher commit')
        assets = [a for a in release['assets'] if a['name'] == 'publisher.json']
        if len(assets) != 1:
            raise ValueError(f'{tag} lacks its publisher.json manifest')
        data = gh.api(f'repos/{PUBLISHER}/releases/assets/{assets[0]["id"]}', binary=True)
        if 'sha256:' + hashlib.sha256(data).hexdigest() != assets[0].get('digest'):
            raise ValueError('Publisher manifest checksum mismatch')
        manifest = json.loads(data)
        if manifest.get('ref') != ref or not all(re.fullmatch('[a-f0-9]{64}', str(manifest.get(key)))
                                                 for key in ('sha256', 'template', 'deploy')):
            raise ValueError(f'{tag} manifest does not identify its own commit and wiring')
        return manifest
    raise ValueError('No immutable publisher release exists')


def download_publisher(ref):
    with urllib.request.urlopen(f'https://raw.githubusercontent.com/{PUBLISHER}/{ref}/release.py', timeout=60) as response:
        return response.read()


def adoptable_publisher(gh, root, revision, *, fetch=download_publisher):
    """The newest publisher (ref, sha256) when a pin-only commit can adopt it; None when the pin is current.

    GITHUB_TOKEN cannot change workflow files, and the new publisher's conform demands its own template
    and deploy command, so a release that changes either needs an owner push and fails here instead.
    """
    command = committed_text(root, revision, '.release/deploy.py') or ''
    pinned = deploy_pin(command)
    if pinned is None:
        raise ValueError('.release/deploy.py has no publisher pin')
    manifest = latest_publisher(gh)
    ref = manifest['ref']
    if ref == pinned[0]:
        return None
    if gh.api(f'repos/{PUBLISHER}/compare/{pinned[0]}...{ref}')['status'] != 'ahead':
        raise ValueError('The newest publisher release does not descend from the pinned publisher')
    workflow = (committed_text(root, revision, WORKFLOW) or '').encode()
    if (hashlib.sha256(workflow).hexdigest() != manifest['template']
            or hashlib.sha256(repin(command, '{ref}', '{sha256}').encode()).hexdigest() != manifest['deploy']):
        raise ValueError(f'Owner action needed: publisher {ref[:12]} changes the CI template or deploy command, which '
                         'GITHUB_TOKEN cannot commit. From a committed, pushed publisher checkout run '
                         'python3 release.py adopt <application>, then review and push the application.')
    if hashlib.sha256(fetch(ref)).hexdigest() != manifest['sha256']:
        raise ValueError('Publisher release checksum mismatch')
    return ref, manifest['sha256']


def refresh(gh, root, revision, repository, *, fetch=download_publisher):
    """Adopt the newest immutable publisher release by moving the single pin in .release/deploy.py."""
    current_main(gh, root, revision, repository)
    adoptable = adoptable_publisher(gh, root, revision, fetch=fetch)
    if adoptable is None:
        print('The publisher pin is current.', flush=True)
        return
    ref, sha256 = adoptable
    path = root / '.release/deploy.py'
    path.write_text(repin(path.read_text(), ref, sha256))
    adopted = commit_as_bot(root, ['.release/deploy.py'], f'Adopt publisher {ref[:12]}')
    push_main(root, repository, gh.token, adopted)
    dispatch(gh, repository, Path(WORKFLOW).name)
    print(f'Pushed {adopted[:12]} adopting publisher {ref[:12]} and requested its release.', flush=True)


def adopt(targets):
    """Point applications at this committed, pushed publisher and install the CI template (no commit)."""
    publisher = Path(__file__).resolve().parent
    if git(publisher, 'status', '--porcelain', '--', 'release.py'):
        raise ValueError('Commit the publisher before applications adopt it')
    ref = git(publisher, 'rev-parse', 'HEAD')
    sha256 = digest(Path(__file__))
    if hashlib.sha256(run(['git', '-C', publisher, 'show', 'HEAD:release.py'], capture=True)).hexdigest() != sha256:
        raise ValueError('Run the committed publisher')
    try:
        run(['git', '-C', publisher, 'merge-base', '--is-ancestor', ref, 'origin/main'], capture=True)
    except RuntimeError:
        raise ValueError('Push the publisher to main first; applications download it from GitHub') from None
    for target in targets:
        root = target.resolve()
        (root / '.release/deploy.py').write_text(deploy_command(ref, sha256))
        workflows = root / '.github/workflows'
        workflows.mkdir(parents=True, exist_ok=True)
        for legacy in [*workflows.glob('*.yml'), *workflows.glob('*.yaml')]:
            if LEGACY_CALLER in legacy.read_text() and legacy != root / WORKFLOW:
                legacy.unlink()
        (root / WORKFLOW).write_text(TEMPLATE)
        print(f'{root.name}: publisher {ref[:12]}; review and commit .release/deploy.py and .github/workflows', flush=True)


def base_candidate(tags, now, base=BASE):
    """The newest cooled-down patch of the pinned nginx minor line, if it differs from the pin."""
    pinned = re.fullmatch(r'docker\.io/library/nginx:(\d+\.\d+)\.(\d+)-alpine-slim@(sha256:[a-f0-9]{64})', base)
    minor, patch = pinned.group(1), int(pinned.group(2))
    eligible = []
    for tag in tags:
        found = re.fullmatch(re.escape(minor) + r'\.(\d+)-alpine-slim', str(tag.get('name')))
        if not found or not re.fullmatch('sha256:[a-f0-9]{64}', str(tag.get('digest'))):
            continue
        pushed = datetime.fromisoformat(tag['tag_last_pushed'].replace('Z', '+00:00'))
        if now - pushed >= timedelta(days=COOLDOWN_DAYS) and int(found.group(1)) >= patch:
            eligible.append((int(found.group(1)), tag['name'], tag['digest']))
    if not eligible:
        return None
    _, name, image_digest = max(eligible)
    candidate = f'docker.io/library/nginx:{name}@{image_digest}'
    return None if candidate == base else candidate


def scan_base(image=BASE):
    """Fail on fixable high or critical vulnerabilities in the runtime base every application image shares."""
    with tempfile.TemporaryDirectory(prefix='base-scan-') as private:
        environment = {**os.environ, **SAFE_ENV}
        run(['docker', 'pull', '--quiet', '--platform', 'linux/amd64', image], env=environment)
        scan_image(image, Path(private), environment)


def rebase(root, candidate):
    """Rewrite release.py's base pin to a newer patch of the same nginx line, and nothing else."""
    pinned = re.fullmatch(r'docker\.io/library/nginx:(\d+\.\d+)\.(\d+)-alpine-slim@sha256:[a-f0-9]{64}', BASE)
    found = re.fullmatch(r'docker\.io/library/nginx:' + re.escape(pinned.group(1))
                         + r'\.(\d+)-alpine-slim@sha256:[a-f0-9]{64}', candidate or '')
    if not found or int(found.group(1)) < int(pinned.group(2)) or candidate == BASE:
        raise ValueError('The base candidate must be a newer digest of the pinned nginx line')
    source = root / 'release.py'
    source.write_text(re.sub(r"^BASE = '[^']+'$", f"BASE = '{candidate}'", source.read_text(), count=1, flags=re.M))


def refresh_base(gh, root):
    """Qualify the newest cooled-down patch without write credentials; apply-base commits it."""
    minor = re.search(r'nginx:(\d+\.\d+)\.', BASE).group(1)
    url = f'https://hub.docker.com/v2/namespaces/library/repositories/nginx/tags?page_size=100&name={minor}.'
    with urllib.request.urlopen(url, timeout=60) as response:
        candidate = base_candidate(json.loads(response.read())['results'], datetime.now(timezone.utc))
    if candidate is None:
        print('The nginx base pin is current.', flush=True)
        return
    current_main(gh, root, git(root, 'rev-parse', 'HEAD'), PUBLISHER)
    scan_base(candidate)
    rebase(root, candidate)
    run([sys.executable, '-m', 'unittest'], cwd=root, timeout=600)
    output('base', candidate)
    print('Qualified base ' + candidate, flush=True)


def apply_base(gh, root, candidate):
    """Commit the qualified base pin to main; nothing is pulled, scanned or tested here."""
    current_main(gh, root, git(root, 'rev-parse', 'HEAD'), PUBLISHER)
    rebase(root, candidate)
    if changed_paths(root) != {'release.py'}:
        raise ValueError('The base refresh must change only release.py')
    refreshed = commit_as_bot(root, ['release.py'], 'Refresh the nginx base to ' + candidate.split(':', 2)[1].split('@')[0])
    push_main(root, PUBLISHER, gh.token, refreshed)
    dispatch(gh, PUBLISHER, 'ci.yml')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', nargs='?', default='deploy', choices=[
        'deploy', 'status', 'verify', 'publish', 'conform', 'audit', 'fix', 'apply-fix', 'refresh',
        'template', 'adopt', 'scan-base', 'refresh-base', 'apply-base'])
    parser.add_argument('targets', nargs='*', type=Path, help='application roots for adopt')
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--artifact', type=Path)
    parser.add_argument('--tree', help='qualified fix tree for apply-fix')
    parser.add_argument('--base', help='qualified base image for apply-base')
    parser.add_argument('--qualifier', default=os.environ.get('RELEASE_QUALIFIER'))
    options = parser.parse_args()
    if options.operation == 'template':
        sys.stdout.write(TEMPLATE)
        return
    if options.operation == 'adopt':
        return adopt(options.targets)
    if options.operation == 'scan-base':
        return scan_base()
    if options.operation == 'refresh-base':
        return refresh_base(GitHub(), Path(__file__).resolve().parent)
    if options.operation == 'apply-base':
        return apply_base(GitHub(), Path(__file__).resolve().parent, options.base)
    if options.operation in ('verify', 'publish', 'fix', 'apply-fix') and options.artifact is None:
        raise ValueError('--artifact is required')
    if not options.qualifier and not os.environ.get('GITHUB_ACTIONS'):
        settings = Path.home() / '.config/app-releases/config.json'
        if settings.exists():
            options.qualifier = json.loads(settings.read_text()).get('qualifier')
    root = options.root.resolve()
    if options.operation in ('deploy', 'verify', 'publish', 'fix'):
        admit(root)
    if options.operation == 'conform':
        # Static standards of the working tree and committed release wiring; builds are checked by verify.
        return require(conform_static(root, json.loads((root / '.release/config.json').read_text()))
                       + conform_repository(root, 'HEAD'))
    revision = git(root, 'rev-parse', 'HEAD')
    pin = deploy_pin(git(root, 'show', revision + ':.release/deploy.py'))
    if not pin or pin[1] != digest(Path(__file__)):
        raise ValueError('Publisher does not match the committed deploy command pin')
    config = json.loads(git(root, 'show', revision + ':.release/config.json'))
    if options.operation == 'audit':
        return audit(GitHub(), root, revision, config)
    repository = config['repository']
    gh = GitHub()
    if not gh.api(f'repos/{repository}')['private'] and not config.get('allowPublicSource'):
        raise ValueError('Local private releases require a private source repository')
    if config.get('allowPublicSource') and not config.get('channel'):
        raise ValueError('Public-source exceptions require a separate release channel')
    if options.operation == 'refresh':
        return refresh(gh, root, revision, repository)
    if options.operation == 'fix':
        return fix(gh, root, revision, repository, config, options.artifact.resolve())
    if options.operation == 'apply-fix':
        return apply_fix(gh, root, revision, repository, config, options.artifact.resolve(), options.tree)
    require_private_package(gh, repository, config)
    done = completed(gh, repository, revision, config)
    if options.operation == 'status':
        if not done:
            print(f'Not published: {repository}@{revision}', flush=True)
        output('published', str(done).lower())
        return
    if done:
        return
    if options.operation in ('deploy', 'publish') and revision != gh.api(f'repos/{repository}/commits/main')['sha']:
        raise ValueError('Push this commit to main before releasing')
    print(f'Releasing committed source {repository}@{revision}; uncommitted edits are excluded.', flush=True)
    if options.operation in ('verify', 'publish'):
        if options.operation == 'verify':
            verify(root, revision, repository, config, options.artifact.resolve(), local=not bool(os.environ.get('GITHUB_ACTIONS')))
        else:
            publish(gh, repository, revision, config, options.artifact.resolve(), options.qualifier)
    else:
        if not options.qualifier and platform.machine() not in ('x86_64', 'AMD64'):
            raise ValueError('Set RELEASE_QUALIFIER to the existing native amd64 qualification host')
        artifacts = CACHE / 'verified' / repository
        artifacts.mkdir(parents=True, exist_ok=True)
        verified = artifacts / revision
        if not verified.exists():
            with tempfile.TemporaryDirectory(prefix='prepare-', dir=artifacts) as temporary:
                prepared = Path(temporary) / 'artifact'
                verify(root, revision, repository, config, prepared)
                if not verified.exists():
                    prepared.rename(verified)
        else:
            print('Reusing the verified artifact; publication rechecks all recorded hashes.', flush=True)
        publish(gh, repository, revision, config, verified, options.qualifier)
        shutil.rmtree(verified)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        main()
    except (RuntimeError, ValueError) as error:
        sys.exit(str(error))
