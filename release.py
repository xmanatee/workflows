#!/usr/bin/env python3
"""The shared local/CI publisher for private static applications (Python 3.12+)."""
import argparse
from contextlib import contextmanager
import hashlib
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
import urllib.error
import urllib.parse
import urllib.request
import uuid

POLICY = 1
BASE = 'docker.io/library/nginx:1.30.6-alpine@sha256:47928bf67eb62a1863cb08d9ecb52d3e704304ba614eaee17884204677702951'
TRIVY = 'ghcr.io/aquasecurity/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222'
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


def read_manifest(gh, repository, release):
    assets = [a for a in release['assets'] if a['name'] == 'release.json']
    if release['draft'] or not release.get('immutable') or len(assets) != 1:
        raise ValueError('A partial, draft or mutable release cannot be reused')
    asset = assets[0]
    data = gh.api(f'repos/{repository}/releases/assets/{asset["id"]}', binary=True)
    if 'sha256:' + hashlib.sha256(data).hexdigest() != asset.get('digest'):
        raise ValueError('Release manifest checksum mismatch')
    return json.loads(data)


def completed(gh, repository, revision, config):
    release = gh.api(f'repos/{repository}/releases/tags/release-{revision}', missing=True)
    if release is None:
        return False
    ref = gh.api(f'repos/{repository}/git/ref/tags/release-{revision}')
    if ref['object']['type'] != 'commit' or ref['object']['sha'] != revision:
        raise ValueError('Release tag does not point to its declared source commit')
    manifest = read_manifest(gh, repository, release)
    qualification = manifest.get('qualification', {})
    if (manifest.get('repository') != repository or manifest.get('revision') != revision
            or qualification.get('policy') != POLICY
            or qualification.get('platform') != 'linux/amd64'
            or any(qualification.get(gate) is not True for gate in ('sourceChecks', 'runtimeSmoke', 'vulnerabilityScan'))
            or set(manifest.get('images', {})) != {'app'}
            or not re.fullmatch(re.escape(config['image']) + r'@sha256:[a-f0-9]{64}',
                                manifest.get('images', {}).get('app', ''))):
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


def toolchain(root, environment):
    expected = (root / '.nvmrc').read_text().strip().removeprefix('v')
    actual = run(['node', '--version'], env=environment, capture=True).decode().strip().removeprefix('v')
    if actual != expected:
        selected = Path.home() / '.nvm/versions/node' / ('v' + expected) / 'bin'
        if not (selected / 'node').is_file():
            raise ValueError(f'Install Node {expected} (see .nvmrc), then retry')
        environment['PATH'] = str(selected) + os.pathsep + environment['PATH']
    package = json.loads((root / 'package.json').read_text())
    if package.get('private') is not True:
        raise ValueError('Application packages must be private')
    manager, version = package['packageManager'].split('@')
    if manager not in ('npm', 'pnpm') or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Pin npm or pnpm to an exact version')
    install = CACHE / 'tools' / (manager + '-' + version)
    executable = install / 'node_modules/.bin' / manager
    if not executable.exists():
        install.mkdir(parents=True, exist_ok=True)
        run(['npm', 'install', '--prefix', install, '--no-package-lock',
             '--no-audit', '--no-fund', manager + '@' + version], cwd=install, env=environment)
    # Nested package scripts must use the same pinned manager.
    environment['PATH'] = str(install / 'node_modules/.bin') + os.pathsep + environment['PATH']
    return [str(executable)]


def scan_source(root, environment):
    name, checksum = LEAKS[(platform.system(), platform.machine())]
    directory = CACHE / ('tools/gitleaks-8.30.1-' + name)
    executable = directory / 'gitleaks'
    if not executable.exists():
        directory.mkdir(parents=True, exist_ok=True)
        url = f'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_{name}.tar.gz'
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != checksum:
            raise ValueError('Gitleaks download checksum mismatch')
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            member = archive.getmember('gitleaks')
            executable.write_bytes(archive.extractfile(member).read())
        executable.chmod(0o755)
    run([executable, 'dir', root, '--redact=100', '--no-banner'], env=environment)


def lint_workflows(root, environment):
    name, checksum = ACTIONLINT[(platform.system(), platform.machine())]
    directory = CACHE / ('tools/actionlint-1.7.12-' + name)
    executable = directory / 'actionlint'
    if not executable.exists():
        directory.mkdir(parents=True, exist_ok=True)
        url = f'https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_{name}.tar.gz'
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != checksum:
            raise ValueError('Actionlint download checksum mismatch')
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            executable.write_bytes(archive.extractfile(archive.getmember('actionlint')).read())
        executable.chmod(0o755)
    run(['shellcheck', '--version'], env=environment)
    workflows = sorted((root / '.github/workflows').glob('*.yml')) + sorted((root / '.github/workflows').glob('*.yaml'))
    run([executable, *workflows], cwd=root, env=environment)


def verify(root, revision, repository, config, output, *, local=True):
    environment = {**os.environ, **SAFE_ENV, 'SOURCE_REVISION': revision}
    # Verification never receives publisher credentials, including through gh's keychain.
    for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN'):
        environment.pop(key, None)
    environment['GH_CONFIG_DIR'] = str(output / 'no-github-credentials')
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='app-source-') as temporary:
        source = Path(temporary)
        # Developer tool links can point outside a repository; they are not build inputs.
        excluded = ['.agents', '.claude', '.codex', '.gemini', '.mcp.json']
        unpack(run(['git', '-C', root, 'archive', revision, '--', '.',
                    *[':(exclude)' + path for path in excluded]], capture=True), source)
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
        manager = toolchain(source, environment)
        install = ['ci'] if Path(manager[0]).name == 'npm' else ['install', '--frozen-lockfile']
        run([*manager, *install], cwd=source, env=environment)
        for command in ['check', *config.get('checks', [])]:
            run([*manager, 'run', command], cwd=source, env=environment, timeout=600)
        for command in config.get('beforeBuild', []):
            run([*manager, *command], cwd=source, env=environment)
        run([*manager, 'run', 'build'], cwd=source, env=environment)
        for relative in config['required']:
            if not safe_path(source, relative).is_file() or not safe_path(source, relative).stat().st_size:
                raise ValueError('Required build output missing: ' + relative)
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
image,expected=sys.argv[1:]
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
  for attempt in range(30):
   try:
    with urllib.request.urlopen('http://127.0.0.1:'+port+'/',timeout=3) as response: data=response.read()
    break
   except OSError:
    if attempt==29: raise
    time.sleep(1)
  assert hashlib.sha256(data).hexdigest()==expected, 'Runtime response differs from verified build'
  run(['docker','exec',name,'nginx','-t'])
 finally:
  subprocess.run(['docker','rm','--force',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  if not existed:
   subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
'''


def qualify(image, expected, remote):
    if remote:
        if not re.fullmatch(r'[a-zA-Z0-9_.@:-]+', remote):
            raise ValueError('Invalid native qualification host')
        command = shlex.join(['sudo', '-n', 'python3', '-c', ACCEPT, image, expected])
        run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', remote, command])
    else:
        architecture = run(['docker', 'version', '--format', '{{.Server.Arch}}'], capture=True).decode().strip()
        if architecture != 'amd64':
            raise ValueError('Set RELEASE_QUALIFIER to a native amd64 host; CPU emulation is not used')
        run(['python3', '-c', ACCEPT, image, expected])


def should_promote(revision, current_main):
    return revision == current_main


def publish(gh, repository, revision, config, output, qualifier):
    record = json.loads((output / 'verified.json').read_text())
    if (record['repository'], record['revision'], record['config'], record['policy']) != (
            repository, revision, config, POLICY):
        raise ValueError('Verified artifact identity mismatch')
    for relative, checksum in record['files'].items():
        if digest(safe_path(output, relative)) != checksum:
            raise ValueError('Verified artifact was modified: ' + relative)
    if {str(p.relative_to(output)) for p in output.rglob('*') if p.is_file() and p.name != 'verified.json'} != set(record['files']):
        raise ValueError('Verified artifact file inventory changed')
    with publication_lock(gh, repository, revision):
        if completed(gh, repository, revision, config):
            return
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
            # A private host umask must not make the served tree unreadable to nginx.
            for path in [output / 'site', *(output / 'site').rglob('*')]:
                path.chmod(0o755 if path.is_dir() else 0o644)
            dockerfile = private / 'Dockerfile'
            dockerfile.write_text(f'FROM {BASE}\nCOPY nginx.conf /etc/nginx/nginx.conf\n'
                'COPY site/ /usr/share/nginx/html/\nHEALTHCHECK --interval=15s --timeout=5s --retries=3 '
                'CMD wget -q --spider http://127.0.0.1/\n')
            tag = config['image'] + ':sha-' + revision
            metadata = private / 'build.json'
            run(['docker', 'buildx', 'build', '--platform', 'linux/amd64', '--push', '--provenance=false',
                 '--tag', tag, '--metadata-file', metadata, '--file', dockerfile, '--label',
                 'org.opencontainers.image.source=https://github.com/' + repository,
                 '--label', 'org.opencontainers.image.revision=' + revision, output], env=environment)
            image = config['image'] + '@' + json.loads(metadata.read_text())['containerimage.digest']
            package = config['image'].removeprefix('ghcr.io/' + repository.split('/')[0] + '/')
            visibility = gh.api(f'users/{repository.split("/")[0]}/packages/container/{package}')['visibility']
            if visibility != 'private':
                raise ValueError('Refusing to release an image in a public package')
            # The native CI worker uses its temporary publisher config for the pull.
            if not qualifier:
                os.environ['DOCKER_CONFIG'] = environment['DOCKER_CONFIG']
            qualify(image, record['files']['site/index.html'], qualifier)
            cache = CACHE / 'trivy'
            cache.mkdir(parents=True, exist_ok=True)
            cache.chmod(0o777)
            environment.update(TRIVY_USERNAME=repository.split('/')[0], TRIVY_PASSWORD=gh.token)
            native = run(['docker', 'version', '--format', '{{.Server.Arch}}'], env=environment, capture=True).decode().strip()
            if native not in ('amd64', 'arm64'):
                raise ValueError('A native amd64 or arm64 Docker worker is required for scanning')
            run(['docker', 'run', '--rm', '--platform', 'linux/' + native, '--user', '65532:65532', '--cap-drop', 'ALL',
                 '--security-opt', 'no-new-privileges', '--env', 'TRIVY_USERNAME', '--env', 'TRIVY_PASSWORD',
                 '--mount', f'type=bind,src={cache},dst=/cache', TRIVY, 'image', '--cache-dir', '/cache',
                 '--image-src', 'remote', '--platform', 'linux/amd64', '--scanners', 'vuln',
                 '--disable-telemetry', '--skip-version-check', '--severity', 'HIGH,CRITICAL',
                 '--ignore-unfixed', '--exit-code', '1', '--timeout', '15m', image], env=environment)
            manifest = {'repository': repository, 'revision': revision, 'images': {'app': image},
                        'qualification': {'policy': POLICY, 'platform': 'linux/amd64',
                                          'sourceChecks': True, 'runtimeSmoke': True, 'vulnerabilityScan': True}}
            manifest_path = private / 'release.json'
            manifest_path.write_text(json.dumps(manifest) + '\n')
            assets = [str(manifest_path)]
            if (output / 'evidence').exists():
                evidence = private / 'evidence.tar.gz'
                with tarfile.open(evidence, 'w:gz') as archive:
                    archive.add(output / 'evidence', arcname='evidence')
                assets.append(str(evidence))
            gh_env = {**environment, 'GH_TOKEN': gh.token}
            release_tag = 'release-' + revision
            reference = gh.api(f'repos/{repository}/git/ref/tags/{release_tag}', missing=True)
            if reference is None:
                gh.api(f'repos/{repository}/git/refs', 'POST', {'ref': 'refs/tags/' + release_tag, 'sha': revision})
            elif reference['object']['type'] != 'commit' or reference['object']['sha'] != revision:
                raise ValueError('Release tag already identifies different source')
            run(['gh', 'release', 'create', release_tag, *assets, '--repo', repository,
                 '--verify-tag', '--title', 'Release ' + revision[:12], '--notes',
                 'Qualified private application image. Deployment follows the existing Ansible poller.',
                 '--draft', '--latest=false'], env=gh_env)
            latest = gh.api(f'repos/{repository}/commits/main')['sha']
            promote = should_promote(revision, latest)
            run(['gh', 'release', 'edit', release_tag, '--repo', repository, '--draft=false',
                 '--latest=' + str(promote).lower()], env=gh_env)
            if not completed(gh, repository, revision, config):
                raise ValueError('Published release could not be verified')
            print('Published for Ansible polling.' if promote else 'Published; newer main exists, latest preserved.')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['deploy', 'status', 'verify', 'publish'], nargs='?', default='deploy')
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--artifact', type=Path)
    parser.add_argument('--qualifier', default=os.environ.get('RELEASE_QUALIFIER'))
    options = parser.parse_args()
    if not options.qualifier and not os.environ.get('GITHUB_ACTIONS'):
        settings = Path.home() / '.config/app-releases/config.json'
        if settings.exists():
            options.qualifier = json.loads(settings.read_text()).get('qualifier')
    root = options.root.resolve()
    revision = git(root, 'rev-parse', 'HEAD')
    pin = re.search(r'^SHA256 = "([a-f0-9]{64})"$',
                    git(root, 'show', revision + ':.release/deploy.py'), re.MULTILINE)
    if not pin or pin.group(1) != digest(Path(__file__)):
        raise ValueError('Publisher does not match the committed deploy command pin')
    config = json.loads(git(root, 'show', revision + ':.release/config.json'))
    repository = config['repository']
    gh = GitHub()
    if not gh.api(f'repos/{repository}')['private']:
        raise ValueError('Local private releases require a private source repository')
    done = completed(gh, repository, revision, config)
    if options.operation == 'status':
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write('published=' + str(done).lower() + '\n')
        return
    if done:
        return
    if options.operation in ('deploy', 'publish') and revision != gh.api(f'repos/{repository}/commits/main')['sha']:
        raise ValueError('Push this commit to main before releasing')
    print(f'Releasing committed source {repository}@{revision}; uncommitted edits are excluded.', flush=True)
    if options.operation in ('verify', 'publish'):
        if options.artifact is None:
            raise ValueError('--artifact is required')
        if options.operation == 'verify':
            verify(root, revision, repository, config, options.artifact.resolve(), local=not bool(os.environ.get('GITHUB_ACTIONS')))
        else:
            publish(gh, repository, revision, config, options.artifact.resolve(), options.qualifier)
    else:
        if not options.qualifier and platform.machine() not in ('x86_64', 'AMD64'):
            raise ValueError('Set RELEASE_QUALIFIER to the existing native amd64 qualification host')
        artifacts = CACHE / 'verified' / repository
        artifacts.mkdir(parents=True, exist_ok=True)
        output = artifacts / revision
        if not output.exists():
            with tempfile.TemporaryDirectory(prefix='prepare-', dir=artifacts) as temporary:
                prepared = Path(temporary) / 'artifact'
                verify(root, revision, repository, config, prepared)
                if not output.exists():
                    prepared.rename(output)
        else:
            print('Reusing the verified artifact; publication rechecks all recorded hashes.', flush=True)
        publish(gh, repository, revision, config, output, options.qualifier)
        shutil.rmtree(output)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        main()
    except (RuntimeError, ValueError) as error:
        sys.exit(str(error))
