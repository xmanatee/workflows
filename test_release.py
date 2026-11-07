from datetime import datetime, timedelta, timezone
import hashlib
import http.server
import re
import io
import json
from pathlib import Path
import tarfile
import threading
import sys
import signal
import time
import tempfile
import unittest
import urllib.request
import subprocess
from unittest.mock import patch

import release


class FakeGitHub:
    def __init__(self):
        self.ref = None
        self.sequence = 0

    def api(self, path, method='GET', body=None, **options):
        if '/git/commits/' in path:
            return {'tree': {'sha': 'tree'}}
        if path.endswith('/git/commits'):
            self.sequence += 1
            return {'sha': str(self.sequence)}
        if method == 'POST':
            if self.ref:
                raise RuntimeError('Conflict')
            self.ref = body['sha']
        elif method == 'DELETE':
            self.ref = None
        else:
            return {'object': {'sha': self.ref}} if self.ref else None


class PublicationTests(unittest.TestCase):
    def test_scan_exports_the_exact_digest_and_retains_security_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            image = 'ghcr.io/owner/app@sha256:' + 'a' * 64
            def run(arguments, **kwargs):
                if arguments[:3] == ['docker', 'image', 'save']:
                    Path(arguments[4]).write_bytes(b'fixture')
                if arguments[:2] == ['docker', 'version']:
                    return b'arm64\n'
            with patch.object(release, 'CACHE', private / 'cache'), patch.object(release, 'run', side_effect=run) as command, \
                    patch.object(release.fcntl, 'flock') as lock:
                release.scan_image(image, private, {})
            self.assertEqual(command.call_args_list[0].args[0],
                             ['docker', 'image', 'save', '--output', private / 'image.tar', image])
            scanner = command.call_args_list[-1].args[0]
            self.assertIn('type=bind,src=' + str(private / 'image.tar') + ',dst=/scan/image.tar,readonly', scanner)
            self.assertIn('--input', scanner)
            self.assertIn('--disable-telemetry', scanner)
            self.assertIn('HIGH,CRITICAL', scanner)
            self.assertEqual(scanner[scanner.index('--exit-code') + 1], '1')
            self.assertNotIn('--image-src', scanner)
            self.assertNotIn('TRIVY_PASSWORD', scanner)
            self.assertIn('--skip-db-update', scanner)
            lock.assert_called_once()

    def test_scanner_database_falls_back_after_a_failed_download_and_never_reads_as_a_finding(self):
        attempts = []
        def run(arguments, **kwargs):
            attempts.append(arguments[arguments.index('--db-repository') + 1])
            if len(attempts) == 1:
                raise RuntimeError('docker failed (exit 1)')
        with patch.object(release, 'run', side_effect=run):
            release.refresh_scanner_database(['trivy'], {})
        self.assertEqual(attempts, list(release.TRIVY_DATABASES))
        with patch.object(release, 'run', side_effect=RuntimeError('docker failed (exit 1)')), \
                patch.object(release.time, 'sleep') as sleep, \
                self.assertRaisesRegex(RuntimeError, 'not a security finding'):
            release.refresh_scanner_database(['trivy'], {})
        self.assertEqual(sleep.call_count, 3)

    def test_image_layers_preserve_all_files_and_normalize_cold_build_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            site = root / 'site'
            model = site / 'speech-models/model/weights.bin'
            model.parent.mkdir(parents=True)
            model.write_bytes(b'verified model')
            (root / 'nginx.conf').write_text('configuration')
            index = site / 'index.html'
            index.write_text('first application')
            (site / 'manifest[1].json').write_text('{}')
            before = {str(p.relative_to(site)): release.digest(p) for p in site.rglob('*') if p.is_file()}
            context = root / 'context'
            dockerfile = release.image_context(root, context, ['speech-models'])
            self.assertIn('COPY --link layers/0/ /', dockerfile)
            emitted = {}
            for layer in (context / 'layers').iterdir():
                served = layer / 'usr/share/nginx/html'
                for path in layer.rglob('*'):
                    if path.is_dir() or layer.name == '0':
                        self.assertEqual(path.stat().st_mtime, 0)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o755 if path.is_dir() else 0o644)
                    if path.is_file():
                        relative = str(path.relative_to(served))
                        self.assertNotIn(relative, emitted)
                        emitted[relative] = release.digest(path)
            self.assertEqual(emitted, before)
            self.assertEqual({str(p.relative_to(site)): release.digest(p)
                              for p in site.rglob('*') if p.is_file()}, before)
            index.write_text('second application')
            self.assertEqual(release.image_context(root, root / 'second', ['speech-models']), dockerfile)
            served_index = root / 'second/layers/1/usr/share/nginx/html/index.html'
            self.assertEqual(served_index.stat().st_mtime_ns, index.stat().st_mtime_ns)
            with self.assertRaisesRegex(ValueError, 'Immutable directories'):
                release.image_context(root, root / 'invalid', ['../outside'])

    def test_web_channels_cannot_collide_with_native_release_tags(self):
        revision = 'a' * 40
        self.assertEqual(release.release_tag(revision, {}), 'release-' + revision)
        self.assertEqual(release.release_tag(revision, {'channel': 'web'}), 'release-web-' + revision)
        with self.assertRaises(ValueError):
            release.release_tag(revision, {'channel': '../native'})

    def test_archived_submodule_uses_the_committed_object_not_local_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            child = root / 'engine'
            child.mkdir(parents=True)
            def git(path, *args):
                return subprocess.check_output(['git', '-C', str(path), '-c', 'user.name=Fixture',
                    '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', *args],
                    stderr=subprocess.DEVNULL, text=True).strip()
            git(child, 'init')
            (child / 'engine.py').write_text('committed engine\n')
            git(child, 'add', '.')
            git(child, 'commit', '-m', 'Engine')
            git(root, 'init')
            git(root, 'add', 'engine')
            git(root, 'commit', '-m', 'Pin engine')
            (child / 'engine.py').write_text('uncommitted changes\n')
            destination = Path(directory) / 'archive'
            destination.mkdir()
            release.archive_source(root, 'HEAD', destination, ['engine'])
            self.assertEqual((destination / 'engine/engine.py').read_text(), 'committed engine\n')
            self.assertEqual((child / 'engine.py').read_text(), 'uncommitted changes\n')

    def test_product_source_inputs_exclude_unrelated_products_and_require_committed_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'source'
            root.mkdir()
            for relative in ['app/index.js', 'operator/catalog.yaml', '.release/config.json', '.nvmrc', 'nginx.conf']:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('committed input\n')
            def git(*args):
                return subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture',
                    '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', *args],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            git('init')
            git('add', '.')
            git('commit', '-m', 'Separate products')
            destination = Path(directory) / 'archive'
            destination.mkdir()
            release.archive_source(root, 'HEAD', destination, inputs=['app'])
            self.assertTrue((destination / 'app/index.js').is_file())
            self.assertTrue((destination / '.release/config.json').is_file())
            self.assertTrue((destination / '.nvmrc').is_file())
            self.assertTrue((destination / 'nginx.conf').is_file())
            self.assertFalse((destination / 'operator').exists())
            with self.assertRaisesRegex(ValueError, 'committed files'):
                release.archive_source(root, 'HEAD', destination, inputs=['missing'])
            with self.assertRaises(ValueError):
                release.archive_source(root, 'HEAD', destination, inputs=['../outside'])

    def test_verified_site_can_contain_its_own_verified_json(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / 'site').mkdir()
            page = output / 'site/verified.json'
            page.write_text('{"public":true}\n')
            config = {'image': 'ghcr.io/owner/app'}
            record = {'repository': 'owner/app', 'revision': 'a' * 40, 'config': config,
                      'policy': release.POLICY, 'files': {'site/verified.json': release.digest(page)}}
            (output / 'verified.json').write_text(json.dumps(record))
            self.assertEqual(release.validate_artifact('owner/app', 'a' * 40, config, output), record)
            page.write_text('{"public":false}\n')
            with self.assertRaisesRegex(ValueError, 'modified'):
                release.validate_artifact('owner/app', 'a' * 40, config, output)
            page.write_text('{"public":true}\n')
            (output / 'site/extra.txt').write_text('unverified')
            with self.assertRaisesRegex(ValueError, 'inventory changed'):
                release.validate_artifact('owner/app', 'a' * 40, config, output)

    def test_public_packages_are_rejected_before_upload(self):
        gh = FakeGitHub()
        with patch.object(gh, 'api', return_value={'visibility': 'public'}):
            with self.assertRaisesRegex(ValueError, 'Refusing to upload'):
                release.require_private_package(gh, 'owner/app', {'image': 'ghcr.io/owner/app'})
        with patch.object(gh, 'api', return_value=None):
            release.require_private_package(gh, 'owner/app', {'image': 'ghcr.io/owner/app'})
        with self.assertRaisesRegex(ValueError, 'source repository owner'):
            release.require_private_package(gh, 'owner/app', {'image': 'ghcr.io/stranger/app'})

    def test_local_and_ci_publishers_cannot_hold_the_same_claim(self):
        gh = FakeGitHub()
        with release.publication_lock(gh, 'owner/app', 'a' * 40):
            owner = gh.ref
            with self.assertRaisesRegex(RuntimeError, 'lock unavailable'):
                with release.publication_lock(gh, 'owner/app', 'a' * 40):
                    self.fail('Second publisher acquired an active claim')
            self.assertEqual(gh.ref, owner)
        self.assertIsNone(gh.ref)

    def test_failed_publisher_releases_its_own_claim(self):
        gh = FakeGitHub()
        with self.assertRaisesRegex(ValueError, 'scan failed'):
            with release.publication_lock(gh, 'owner/app', 'a' * 40):
                raise ValueError('scan failed')
        self.assertIsNone(gh.ref)

    def test_only_current_main_can_become_latest(self):
        self.assertTrue(release.should_promote('current', 'current'))
        self.assertFalse(release.should_promote('older', 'current'))

    def test_partial_and_tampered_releases_are_not_successful(self):
        gh = FakeGitHub()
        for metadata in [{'draft': True, 'immutable': False, 'assets': []},
                         {'draft': False, 'immutable': True, 'assets': []}]:
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                release.read_manifest(gh, 'owner/app', metadata)
        metadata = {'draft': False, 'immutable': True,
                    'assets': [{'id': 1, 'name': 'release.json', 'digest': 'sha256:' + '0' * 64}]}
        with patch.object(gh, 'api', return_value=b'{}'), self.assertRaisesRegex(ValueError, 'checksum'):
            release.read_manifest(gh, 'owner/app', metadata)

    def test_completed_release_skips_without_a_lock_or_build(self):
        revision = 'a' * 40
        config = {'image': 'ghcr.io/owner/app', 'health': [HEALTH]}
        manifest = {'repository': 'owner/app', 'revision': revision,
                    'images': {'app': 'ghcr.io/owner/app@sha256:' + 'b' * 64},
                    'qualification': {'policy': release.POLICY, 'platform': 'linux/amd64',
                                      'sourceChecks': True, 'runtimeSmoke': True, 'vulnerabilityScan': True},
                    'health': [{'host': HEALTH['host'], 'path': '/', 'sha256': 'c' * 64, 'marker': HEALTH['marker']}]}
        def published(manifest):
            data = json.dumps(manifest).encode()
            return {'draft': False, 'immutable': True, 'html_url': 'https://example.invalid/release',
                    'assets': [{'id': 1, 'name': 'release.json',
                                'digest': 'sha256:' + hashlib.sha256(data).hexdigest()}]}, data
        metadata, data = published(manifest)
        gh = FakeGitHub()
        ref = {'object': {'type': 'commit', 'sha': revision, 'url': 'https://example.invalid/commit'}}
        with patch.object(gh, 'api', side_effect=[metadata, ref, data]) as api:
            self.assertTrue(release.completed(gh, 'owner/app', revision, config))
            self.assertEqual(api.call_count, 3)
        with patch.object(gh, 'api', side_effect=[metadata, {'object': {'type': 'commit', 'sha': 'wrong'}}]):
            with self.assertRaisesRegex(ValueError, 'tag does not point'):
                release.completed(gh, 'owner/app', revision, config)
        for health in [None, [], [{**manifest['health'][0], 'sha256': 'short'}],
                       [{**manifest['health'][0], 'marker': 'other'}], [{**manifest['health'][0], 'sso': True}]]:
            metadata, data = published({**manifest, 'health': health})
            with self.subTest(health=health), patch.object(gh, 'api', side_effect=[metadata, ref, data]), \
                    self.assertRaisesRegex(ValueError, 'qualification policy'):
                release.completed(gh, 'owner/app', revision, config)

    def test_manifest_health_pins_each_check_to_its_verified_file(self):
        config = {'health': [HEALTH, {'host': 'sandbox.example.org', 'path': '/sw.js', 'file': 'sw.js',
                                      'marker': 'worker', 'sso': True}]}
        record = {'files': {'site/index.html': 'a' * 64, 'site/sw.js': 'b' * 64}}
        self.assertEqual(release.health_manifest(config, record), [
            {'host': 'app.example.org', 'path': '/', 'sha256': 'a' * 64, 'marker': HEALTH['marker']},
            {'host': 'sandbox.example.org', 'path': '/sw.js', 'sha256': 'b' * 64, 'marker': 'worker', 'sso': True}])
        with self.assertRaisesRegex(ValueError, 'not part of the verified output'):
            release.health_manifest(config, {'files': {'site/index.html': 'a' * 64}})

    def test_native_smoke_cannot_follow_redirects_or_environment_proxies(self):
        body = b'verified site'
        requests = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(302 if self.path == '/redirect' else 200)
                if self.path == '/redirect':
                    self.send_header('Location', '/escape')
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        def accept(path, selected_port=port, proxy=False):
            def docker(args, **kwargs):
                output = f'127.0.0.1:{selected_port}\n'.encode() if args[1] == 'port' else b''
                return subprocess.CompletedProcess(args, 0, output)
            checks = [{'path': path, 'sha256': hashlib.sha256(body).hexdigest()}]
            environment = {'http_proxy': f'http://127.0.0.1:{port}'} if proxy else {}
            with patch.object(subprocess, 'run', side_effect=docker), \
                    patch.object(release.platform, 'machine', return_value='x86_64'), \
                    patch.object(signal, 'signal'), patch.object(time, 'sleep'), \
                    patch.object(sys, 'argv', ['accept', 'fixture@sha256:abc', json.dumps(checks)]), \
                    patch.dict(release.os.environ, environment, clear=True), \
                    patch.object(urllib.request, '_opener', None):
                exec(compile(release.ACCEPT, '<native smoke>', 'exec'), {})
        accept('/')
        self.assertEqual(requests, ['/'])
        requests.clear()
        with self.subTest('redirect'), self.assertRaises(urllib.error.HTTPError):
            accept('/redirect')
        with self.subTest('redirect target'):
            self.assertNotIn('/escape', requests)
        requests.clear()
        # The origin is closed; a matching response from the configured proxy must fail.
        with self.subTest('proxy'), self.assertRaises(urllib.error.URLError):
            accept('/', selected_port=0, proxy=True)
        with self.subTest('proxy target'):
            self.assertEqual(requests, [])

    def test_credentials_do_not_follow_asset_redirects(self):
        original = urllib.request.Request('https://api.github.com/repos/owner/app/releases/assets/1',
                                          headers={'Authorization': 'Bearer fixture'})
        redirected = release.SafeRedirect().redirect_request(original, None, 302, '', {},
                                                              'https://release-assets.githubusercontent.com/asset')
        self.assertFalse(redirected.has_header('Authorization'))

    def test_artifact_paths_and_archives_cannot_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                release.safe_path(root, '../outside')
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as archive:
                member = tarfile.TarInfo('../escaped')
                archive.addfile(member, io.BytesIO(b''))
            with self.assertRaises(tarfile.FilterError):
                release.unpack(data.getvalue(), root)


class AuditTests(unittest.TestCase):
    def test_schedule_audits_committed_locks_every_time_without_publisher_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'repository'
            (root / '.release').mkdir(parents=True)
            (root / '.release/config.json').write_text(json.dumps({'repository': 'owner/app', 'audit': ['audit']}))
            (root / '.release/deploy.py').write_text(release.deploy_command('a' * 40, release.digest(Path(release.__file__))))
            (root / 'locked.txt').write_text('vulnerable')
            (root / 'manager.py').write_text("""import os,sys
from pathlib import Path
assert sys.argv[1:] == ['audit'], 'Only the audit may run'
assert not any(os.environ.get(key) for key in ('GH_TOKEN','GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN',
    'OPENAI_API_KEY','ELEVENLABS_API_KEY','HOL_UNLOCK_CODE'))
assert not Path(os.environ['GH_CONFIG_DIR']).exists()
if Path('locked.txt').read_text() != 'fixed': sys.exit(9)
with Path(os.environ['AUDIT_MARKER']).open('a') as marker: marker.write('audit\\n')
""")
            def git(*args):
                subprocess.run(['git', '-C', root, '-c', 'user.name=Fixture',
                    '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', *args],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            git('init')
            git('add', '.')
            git('commit', '-m', 'Commit vulnerable lockfile')
            # An uncommitted fix must not hide a finding in the committed dependency graph.
            (root / 'locked.txt').write_text('fixed')
            marker = Path(directory) / 'audits'
            def toolchain(source, *_):
                return [sys.executable, str(source / 'manager.py')]
            previous_umask = release.os.umask(0o077)
            self.addCleanup(release.os.umask, previous_umask)
            gh = object()
            adoption = []
            with patch.object(sys, 'argv', ['release', 'audit', '--root', str(root)]), \
                    patch.object(release, 'toolchain', side_effect=toolchain), \
                    patch.object(release, 'conform_repository', return_value=[]), \
                    patch.object(release, 'conform_static', return_value=[]), \
                    patch.object(release, 'GitHub', return_value=gh), \
                    patch.object(release, 'adoptable_publisher', side_effect=lambda *args: adoption.append(args)), \
                    patch.dict(release.os.environ, {'GH_TOKEN': 'fixture', 'GITHUB_TOKEN': 'fixture',
                        'ACTIONS_RUNTIME_TOKEN': 'fixture', 'OPENAI_API_KEY': 'fixture',
                        'ELEVENLABS_API_KEY': 'fixture', 'HOL_UNLOCK_CODE': 'fixture', 'AUDIT_MARKER': str(marker)}):
                with self.assertRaisesRegex(RuntimeError, 'exit 9'):
                    release.main()
                self.assertFalse(marker.exists())
                git('add', 'locked.txt')
                git('commit', '-m', 'Qualify fixed lockfile')
                release.main()
                release.main()
            self.assertEqual(marker.read_text().splitlines(), ['audit', 'audit'])
            # Only the publisher adoption check reads GitHub; the dependency audit above saw no credentials.
            self.assertEqual([args[0] for args in adoption], [gh, gh, gh])


HEALTH = {'host': 'app.example.org', 'path': '/', 'file': 'index.html', 'marker': '<title>Application</title>'}
CONFIG = {'dist': 'dist', 'audit': ['audit'], 'health': [HEALTH]}
SANE = "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
NGINX = f'add_header Content-Security-Policy "script-src \'self\'; connect-src \'self\' https://api.example.org; {SANE}";'


def policy(**directives):
    return 'add_header Content-Security-Policy "' + '; '.join(
        f'{name} {sources}' for name, sources in directives.items()) + f'; {SANE}";'


def conform(root, config):
    release.require(release.conform_static(root, config) + release.conform_bundle(root, config))


class ToolCacheTests(unittest.TestCase):
    """CI restores tool caches from shared state, so a cached tool runs only after it matches its reference again."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / 'app'
        self.root.mkdir()
        (self.root / '.nvmrc').write_text('24.0.0\n')
        (self.root / 'package.json').write_text(json.dumps({'private': True, 'packageManager': 'pnpm@11.1.0'}))
        self.cache = Path(directory.name) / 'cache'
        cache = patch.object(release, 'CACHE', self.cache)
        cache.start()
        self.addCleanup(cache.stop)
        self.tarball = b'genuine pnpm tarball'
        self.integrity = 'sha512-' + __import__('base64').b64encode(hashlib.sha512(self.tarball).digest()).decode()
        self.downloads, self.installs = [], []
        self.served = self.tarball

    def urlopen(self, url, timeout):
        self.downloads.append(url)
        return io.BytesIO(self.served)

    def command(self, args, *, cwd=None, env=None, capture=False, **options):
        args = [str(argument) for argument in args]
        if args[:2] == ['node', '--version']:
            return b'v24.0.0\n'
        if args[:2] == ['npm', 'view']:
            return json.dumps({'dist.tarball': 'https://registry.npmjs.org/pnpm/-/pnpm-11.1.0.tgz',
                               'dist.integrity': self.integrity}).encode()
        if args[:2] == ['npm', 'install']:
            self.installs.append(Path(args[-1]).read_bytes())
            prefix = Path(args[args.index('--prefix') + 1])
            self.assertEqual(sorted(path.name for path in prefix.iterdir()), ['package.json'])
            (prefix / 'node_modules/.bin').mkdir(parents=True)
            (prefix / 'node_modules/.bin/pnpm').write_text('installed from the verified tarball')
            return b''
        raise AssertionError(args)

    def toolchain(self):
        with patch.object(release, 'run', side_effect=self.command), patch('urllib.request.urlopen', side_effect=self.urlopen):
            return release.toolchain(self.root, {'PATH': '/usr/bin'})

    def test_the_manager_is_reinstalled_from_a_tarball_matching_the_registry_integrity(self):
        executable, = self.toolchain()
        self.assertEqual(Path(executable).read_text(), 'installed from the verified tarball')
        self.assertEqual(len(self.downloads), 1)
        # A restored install tree is never trusted, and a matching cached tarball is not downloaded again.
        Path(executable).write_text('poisoned')
        self.toolchain()
        self.assertEqual(Path(executable).read_text(), 'installed from the verified tarball')
        self.assertEqual(len(self.downloads), 1)
        # A tampered cached tarball is replaced by the registry's.
        (self.cache / 'tools/pnpm-11.1.0.tgz').write_bytes(b'poisoned tarball')
        self.toolchain()
        self.assertEqual(len(self.downloads), 2)
        self.assertEqual(self.installs, [self.tarball] * 3)

    def test_a_download_that_does_not_match_its_reference_never_installs(self):
        self.served = b'substituted tarball'
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            self.toolchain()
        self.assertEqual(self.installs, [])
        self.assertFalse((self.cache / 'tools/pnpm-11.1.0.tgz').exists())

    def test_pinned_executables_are_extracted_from_their_verified_archive_on_every_use(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            content = b'genuine scanner'
            member = tarfile.TarInfo('gitleaks')
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        self.served = buffer.getvalue()
        checksum = hashlib.sha256(self.served).hexdigest()
        with patch('urllib.request.urlopen', side_effect=self.urlopen):
            executable = release.pinned_executable('gitleaks-test', 'https://example.test/gitleaks.tar.gz', checksum, 'gitleaks')
            executable.write_bytes(b'poisoned scanner')
            executable = release.pinned_executable('gitleaks-test', 'https://example.test/gitleaks.tar.gz', checksum, 'gitleaks')
            self.assertEqual(executable.read_bytes(), b'genuine scanner')
            self.assertEqual(len(self.downloads), 1)
            (executable.parent / 'release.tar.gz').write_bytes(b'poisoned archive')
            release.pinned_executable('gitleaks-test', 'https://example.test/gitleaks.tar.gz', checksum, 'gitleaks')
            self.assertEqual(len(self.downloads), 2)
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                release.pinned_executable('gitleaks-test', 'https://example.test/gitleaks.tar.gz', '0' * 64, 'gitleaks')

    def test_the_audit_job_restores_but_never_saves_the_shared_tool_cache(self):
        audit = re.search(r'^  audit:\n(.*?)(?=^  [\w-]+:\n)', release.TEMPLATE, re.M | re.S)[1]
        self.assertIn('actions/cache/restore@', audit)
        self.assertNotRegex(audit, r'actions/cache@')


class ConformTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.write('package.json', json.dumps({'private': True, 'packageManager': 'npm@12.2.0', 'scripts': {
            'check': 'tsc', 'build': 'vite build', 'check:all': 'python3 ../../tools/heavy -- npm run check'}}))
        self.write('package-lock.json', '{}')
        self.write('.nvmrc', '22.23.4')
        self.write('.npmrc', 'min-release-age=7\n')
        self.write('nginx.conf', NGINX)
        self.write('dist/index.html', '<title>Application</title><script src="/assets/a.js"></script>'
                   '<link rel="stylesheet" href="/a.css">')
        self.write('dist/assets/a.js', 'fetch("https://api.example.org/x");"http://www.w3.org/2000/svg"')

    def tearDown(self):
        self.directory.cleanup()

    def write(self, name, text):
        (self.root / name).parent.mkdir(parents=True, exist_ok=True)
        (self.root / name).write_text(text)

    def scripts(self, **changes):
        package = json.loads((self.root / 'package.json').read_text())
        package['scripts'].update(changes)
        self.write('package.json', json.dumps(package))

    def test_a_conforming_application_passes(self):
        conform(self.root, CONFIG)

    def test_heavy_entrypoints_admit_themselves(self):
        self.scripts(**{'test:e2e': 'playwright test', 'bench': 'node bench.mjs', 'image': 'docker buildx build .',
                        'test:browser': 'python3 ../../tools/heavy -- playwright test', 'lint': 'eslint .'})
        issues = release.conform_scripts(self.root, CONFIG)
        self.assertEqual(sorted(issue.split()[1] for issue in issues if 'heavy entrypoint' in issue),
                         ['bench', 'image', 'test:e2e'])

    def test_health_declarations_are_complete_and_safe(self):
        self.assertEqual(release.conform_health(CONFIG), [])
        self.assertIn('smoke is replaced by health', ' '.join(release.conform_health({**CONFIG, 'smoke': []})))
        for health in [None, [], [{}], [{**HEALTH, 'extra': 1}], [{**HEALTH, 'host': 'App.example.org'}],
                       [{**HEALTH, 'host': 'localhost'}], [{**HEALTH, 'path': '//evil.example'}],
                       [{**HEALTH, 'path': '/${HOME}'}], [{**HEALTH, 'path': '/a$b'}], [{**HEALTH, 'path': 'relative'}],
                       [{**HEALTH, 'path': '/?q=1'}], [{**HEALTH, 'file': '../outside'}], [{**HEALTH, 'marker': ''}],
                       [{**HEALTH, 'marker': 'a*b'}], [{**HEALTH, 'sso': False}], [HEALTH, HEALTH]]:
            with self.subTest(health=health):
                self.assertTrue(release.conform_health({**CONFIG, 'health': health}))
        self.assertEqual(release.conform_health({**CONFIG, 'health': [{**HEALTH, 'sso': True}]}), [])
        for path in ['/', '/sw.js', '/__canvas__/qualification', "/a-b_c.d~e!&'()+,;=:@%20/"]:
            with self.subTest(path=path):
                self.assertEqual(release.conform_health({**CONFIG, 'health': [{**HEALTH, 'path': path}]}), [])

    def test_markers_stay_literal_inside_gatus_conditions(self):
        for marker in ['<title>Sups', '<title>Vostok</title>', 'Crescent Visibility Map</title>', 'Pub FS Service Worker',
                       'a<b', 'x=1', 'a!=b', '"quoted" & (grouped) | piped', 'x' * 128]:
            with self.subTest(marker=marker):
                self.assertEqual(release.conform_health({**CONFIG, 'health': [{**HEALTH, 'marker': marker}]}), [])
        for marker in ['', 'x' * 129, '${HOME}', 'a$b', 'a*b', 'a?b', '[BODY]', 'a\\b', ' lead', 'trail ', 'tab\there',
                       'line\nbreak', 'café', 'a == b', 'a != b', 'a <= b', 'a >= b', 'a < b', 'a > b', '\x7f']:
            with self.subTest(marker=marker):
                self.assertIn('marker must be', ' '.join(release.conform_health({**CONFIG, 'health': [{**HEALTH, 'marker': marker}]})))

    def test_bundle_must_carry_each_health_marker(self):
        self.write('dist/index.html', '<title>Renamed</title>')
        self.assertIn('lacks the health marker', ' '.join(release.conform_bundle(self.root, CONFIG)))

    def test_browser_events_need_a_boolean_and_the_vendored_client(self):
        self.assertIn('.release/config.json browserEvents must be a boolean', release.conform_release({**CONFIG, 'browserEvents': 'yes'}))
        config = {**CONFIG, 'browserEvents': True}
        self.assertIn('vendored client', ' '.join(release.conform_bundle(self.root, config)))
        self.write('dist/assets/a.js', 'navigator.sendBeacon("/_/events",body)')
        self.assertEqual(release.conform_bundle(self.root, config), [])

    def test_script_origins_and_evaluation_need_declared_reasons(self):
        self.write('nginx.conf', policy(**{'script-src': "'self' 'unsafe-eval' https://cdn.example.net blob: 'wasm-unsafe-eval'",
                                           'connect-src': "'self'"}))
        issues = release.conform_nginx(self.root, CONFIG)
        self.assertIn("nginx.conf script-src 'unsafe-eval' needs a scriptExceptions reason", issues)
        self.assertIn('nginx.conf script-src https://cdn.example.net needs a scriptOrigins reason', issues)
        declared = {**CONFIG, 'scriptOrigins': {'https://cdn.example.net': 'Pinned runtime'},
                    'scriptExceptions': {'unsafe-eval': 'Compiles schemas'}}
        self.assertEqual(release.conform_nginx(self.root, declared), [])
        stale = {**declared, 'scriptExceptions': {'unsafe-eval': 'Compiles schemas', 'unsafe-inline': 'Old shell'}}
        self.assertIn('.release/config.json declares unused script source unsafe-inline', release.conform_nginx(self.root, stale))
        for bad in [{'scriptOrigins': {'https://cdn.example.net': ''}}, {'scriptOrigins': ['https://cdn.example.net']},
                    {'scriptOrigins': {'https://*.example.net': 'wildcard'}}, {'scriptExceptions': {'unsafe-hashes': 'x'}}]:
            with self.subTest(bad=bad):
                self.assertTrue(release.conform_nginx(self.root, {**declared, **bad}))
        self.write('nginx.conf', policy(**{'script-src': "'self' data:", 'connect-src': "'self'"}))
        self.assertIn('nginx.conf script-src allows the whole scheme or wildcard data:', release.conform_nginx(self.root, CONFIG))

    def test_policies_restrict_plugins_base_and_framing(self):
        for sane, expected in [("base-uri 'self'; frame-ancestors 'none'", 'object-src'),
                               ("object-src 'self'; base-uri 'self'; frame-ancestors 'none'", 'object-src'),
                               ("object-src 'none'; frame-ancestors 'none'", 'base-uri'),
                               ("object-src 'none'; base-uri https://cdn.example.net; frame-ancestors 'none'", 'base-uri'),
                               ("object-src 'none'; base-uri 'self'", 'frame-ancestors'),
                               ("object-src 'none'; base-uri 'self'; frame-ancestors *", 'frame-ancestors'),
                               ("object-src 'none'; base-uri 'self'; frame-ancestors https:", 'frame-ancestors'),
                               ("object-src 'none'; base-uri 'self'; frame-ancestors 'none' 'self'", 'frame-ancestors')]:
            self.write('nginx.conf', f'add_header Content-Security-Policy "script-src \'self\'; connect-src \'self\'; {sane}";')
            with self.subTest(sane=sane):
                self.assertTrue(any(expected in issue for issue in release.conform_nginx(self.root, CONFIG)))
        self.write('nginx.conf', 'add_header Content-Security-Policy "script-src \'self\'; connect-src \'self\'; '
                   "object-src 'none'; base-uri 'none'; frame-ancestors 'self' https://web.telegram.org\";")
        self.assertEqual(release.conform_nginx(self.root, CONFIG), [])

    def test_required_scripts_and_the_heavy_wrapper(self):
        self.write('package.json', json.dumps({'private': True, 'packageManager': 'npm@12.2.0', 'scripts': {'check': 'tsc'}}))
        issues = release.conform_scripts(self.root, CONFIG)
        self.assertIn('Missing package script: build', issues)
        self.assertTrue(any('tools/heavy' in issue for issue in issues))

    def test_check_may_not_reach_browsers_even_through_delegated_scripts(self):
        self.scripts(check='npm run verify', verify='playwright test')
        self.assertTrue(any('playwright' in issue for issue in release.conform_scripts(self.root, CONFIG)))
        self.write('tooling/tasks.mjs', 'const tasks = {\n  check: () => {\n    tasks["test:e2e"]();\n  },\n'
                   '  "test:e2e": () => exec("playwright"),\n  other: () => {},\n};\n')
        self.scripts(check='node tooling/tasks.mjs check')
        self.assertTrue(any('e2e' in issue for issue in release.conform_scripts(self.root, CONFIG)))
        self.write('tooling/tasks.mjs', 'const tasks = {\n  check: () => lint(),\n  "test:e2e": () => exec("playwright"),\n};\n')
        self.scripts(verify='python3 ../../tools/heavy -- playwright test')
        self.assertEqual(release.conform_scripts(self.root, CONFIG), [])

    def test_package_manager_toolchain_and_cooldown(self):
        self.write('pnpm-lock.yaml', '')
        (self.root / '.nvmrc').unlink()
        (self.root / '.npmrc').write_text('min-release-age=0\n')
        self.assertEqual(len(release.conform_package(self.root, self.root, CONFIG)), 3)
        self.write('package.json', json.dumps({'packageManager': 'npm@12', 'scripts': {}}))
        self.assertTrue(release.conform_package(self.root, self.root, CONFIG)[-1].startswith('Pin exactly one'))

    def test_pnpm_cooldown_and_private_workspace_packages(self):
        self.write('package.json', json.dumps({'private': True, 'packageManager': 'pnpm@12.11.2', 'scripts': {}}))
        (self.root / 'package-lock.json').rename(self.root / 'pnpm-lock.yaml')
        self.write('packages/a/package.json', '{}')
        self.write('pnpm-workspace.yaml', 'minimumReleaseAge: 10080\n')
        self.assertEqual(release.conform_package(self.root, self.root, CONFIG), ['packages/a/package.json must declare private: true'])
        self.write('packages/a/package.json', '{"private": true}')
        self.assertEqual(release.conform_package(self.root, self.root, CONFIG), [])
        for setting in ['minimumReleaseAge: 1440\n', 'minimumReleaseAge: 20160\n']:
            self.write('pnpm-workspace.yaml', setting)
            with self.subTest(setting=setting):
                self.assertIn('uniform 7-day', ' '.join(release.conform_package(self.root, self.root, CONFIG)))
        self.write('pnpm-workspace.yaml', 'minimumReleaseAge: 10080\n')
        self.write('package.json', json.dumps({'private': True, 'packageManager': 'pnpm@10.34.7', 'scripts': {}}))
        self.assertIn('Pin pnpm 11 or newer', ' '.join(release.conform_package(self.root, self.root, CONFIG)))

    def test_audit_gate(self):
        self.assertIn('.release/config.json audit must name the dependency audit command', release.conform_release(CONFIG | {'audit': []}))
        self.assertEqual(release.conform_release({**CONFIG, 'audit': ['exec', 'node', 'scripts/audit-dependencies.mjs']}), [])

    def test_bundle_rejects_telemetry_and_external_assets_but_not_a_mentioned_url(self):
        self.write('dist/assets/b.js', 'a="https://o1.ingest.sentry.io/1";b="https://docs.example.net/p"')
        self.write('dist/index.html', '<link rel="stylesheet" href="https://fonts.googleapis.com/css"><script src="//cdn.test/x.js"></script>')
        issues = '\n'.join(release.conform_bundle(self.root, CONFIG))
        for expected in ('sentry.io', 'fonts.googleapis.com', '//cdn.test/x.js'):
            self.assertIn(expected, issues)
        for mentioned in ('www.w3.org', 'api.example.org', 'docs.example.net'):
            self.assertNotIn(mentioned, issues)

    def test_firebase_naming_its_sdks_is_not_analytics_but_the_sdk_is(self):
        self.write('dist/index.html', '<title>Application</title><script src="/assets/b.js"></script>')
        self.write('dist/assets/b.js', 'r={"@firebase/analytics":"fire-analytics"}')
        self.assertEqual(release.conform_bundle(self.root, CONFIG), [])
        self.write('dist/assets/b.js', 'u="https://www.googletagmanager.com/gtag/js"')
        self.assertIn('googletagmanager', '\n'.join(release.conform_bundle(self.root, CONFIG)))

    def test_custom_https_api_endpoints_need_an_explicit_boolean_capability(self):
        self.write('nginx.conf', policy(**{'script-src': "'self'", 'connect-src': "'self' https:"}))
        conform(self.root, {**CONFIG, 'customApiEndpoints': True})
        for config in (CONFIG, {**CONFIG, 'customApiEndpoints': False}):
            with self.subTest(config=config), self.assertRaisesRegex(ValueError, 'connect-src.*https:'):
                conform(self.root, config)
        for value in ('true', 1, None, []):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'customApiEndpoints must be a boolean'):
                conform(self.root, {**CONFIG, 'customApiEndpoints': value})

    def test_custom_api_capability_does_not_allow_other_schemes_scripts_or_wildcards(self):
        config = {**CONFIG, 'customApiEndpoints': True}
        for directive, source in [('script-src', 'https:'), ('script-src', 'http:'),
                ('script-src', 'wss:'), ('script-src', 'https://*'), ('script-src', '*'),
                ('connect-src', 'http:'), ('connect-src', 'wss:'),
                ('connect-src', 'https://*'), ('connect-src', '*')]:
            sources = {'script-src': "'self'", 'connect-src': "'self' https:"}
            sources[directive] += ' ' + source
            self.write('nginx.conf', policy(**sources))
            with self.subTest(directive=directive, source=source), self.assertRaisesRegex(ValueError, directive):
                conform(self.root, config)

    def test_custom_api_capability_keeps_telemetry_rejection(self):
        self.write('nginx.conf', policy(**{'script-src': "'self'", 'connect-src': "'self' https:"}))
        self.write('dist/assets/b.js', 'u="https://o1.ingest.sentry.io/1"')
        with self.assertRaisesRegex(ValueError, 'telemetry marker sentry.io'):
            conform(self.root, {**CONFIG, 'customApiEndpoints': True})

    def test_nginx_policy_names_each_origin(self):
        self.assertEqual(release.conform_nginx(self.root, CONFIG), [])
        for source in ('https:', 'wss:', '*', 'https://*'):
            with self.subTest(source=source):
                self.write('nginx.conf', policy(**{'script-src': "'self'", 'connect-src': f"'self' data: {source}"}))
                self.assertEqual(release.conform_nginx(self.root, CONFIG), [f'nginx.conf connect-src allows the whole scheme or wildcard {source}'])
        self.write('nginx.conf', policy(**{'connect-src': "'self' wss://other.test"}))
        self.assertEqual(release.conform_nginx(self.root, CONFIG), ['nginx.conf needs a Content-Security-Policy with script-src'])
        self.write('nginx.conf', 'server {}')
        self.assertEqual(len(release.conform_nginx(self.root, CONFIG)), 2)


def git_fixture(root):
    def git(*args):
        return subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                               '-c', 'commit.gpgsign=false', *args], check=True, capture_output=True, text=True).stdout.strip()
    git('init', '--quiet', '--initial-branch=main')
    return git


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.git = git_fixture(self.root)
        self.write(release.WORKFLOW, release.TEMPLATE)
        self.write('.release/deploy.py', release.deploy_command('a' * 40, 'b' * 64))

    def write(self, name, text):
        (self.root / name).parent.mkdir(parents=True, exist_ok=True)
        (self.root / name).write_text(text)

    def commit(self):
        self.git('add', '--all')
        self.git('commit', '--quiet', '--allow-empty', '-m', 'Fixture')
        return release.conform_repository(self.root, 'HEAD')

    def test_the_committed_template_and_single_pin_conform(self):
        self.assertEqual(self.commit(), [])

    def test_template_drift_and_the_retired_caller_are_rejected(self):
        self.write(release.WORKFLOW, release.TEMPLATE.replace("'17 5 * * *'", "'18 5 * * *'"))
        self.write('.github/workflows/ci.yml', f'jobs:\n  release:\n    uses: {release.LEGACY_CALLER}@abc\n')
        issues = self.commit()
        self.assertIn(f'{release.WORKFLOW} must equal the publisher template (python3 .release/deploy.py template)', issues)
        self.assertIn('.github/workflows/ci.yml calls the retired shared release workflow', issues)

    def test_uncommitted_files_do_not_count(self):
        self.commit()
        (self.root / release.WORKFLOW).unlink()
        self.assertEqual(release.conform_repository(self.root, 'HEAD'), [])

    def test_scheduled_heavy_workflows_stay_local(self):
        self.write('.github/workflows/nightly.yml', 'on:\n  schedule:\n    - cron: "0 3 * * *"\njobs:\n  x:\n    run: npm run check:all\n')
        self.assertEqual(self.commit(), ['nightly.yml schedules heavy work; keep it local'])

    def test_the_deploy_command_carries_only_its_pin(self):
        self.write('.release/deploy.py', release.deploy_command('a' * 40, 'b' * 64) + 'print("extra")\n')
        self.assertIn('.release/deploy.py must be the publisher deploy command with only its REF and SHA256 pin', self.commit())
        self.assertEqual(release.deploy_pin(release.deploy_command('c' * 40, 'd' * 64)), ('c' * 40, 'd' * 64))

    def test_adopt_pins_the_pushed_publisher_and_replaces_the_retired_caller(self):
        self.write('.github/workflows/ci.yml', f'jobs:\n  release:\n    uses: {release.LEGACY_CALLER}@abc\n')
        self.write('.github/workflows/pages.yml', 'jobs: {}\n')
        (self.root / release.WORKFLOW).unlink()
        publisher = Path(release.__file__).resolve().parent
        def git(root, *args):
            if args[:2] == ('status', '--porcelain'):
                return ''
            if args == ('rev-parse', 'HEAD'):
                return 'e' * 40
            raise AssertionError(args)
        def run(args, capture=False, **kwargs):
            if args[3:5] == ['show', 'HEAD:release.py']:
                return Path(release.__file__).read_bytes()
            self.assertEqual(args[3:], ['merge-base', '--is-ancestor', 'e' * 40, 'origin/main'])
        with patch.object(release, 'git', side_effect=git), patch.object(release, 'run', side_effect=run):
            release.adopt([self.root])
        self.assertEqual(release.deploy_pin((self.root / '.release/deploy.py').read_text()),
                         ('e' * 40, release.digest(publisher / 'release.py')))
        self.assertEqual((self.root / release.WORKFLOW).read_text(), release.TEMPLATE)
        self.assertFalse((self.root / '.github/workflows/ci.yml').exists())
        self.assertTrue((self.root / '.github/workflows/pages.yml').exists())


class MaintenanceGitHub:
    token = 'fixture-token'

    def __init__(self, main, releases=(), assets=None, tags=None, compare='ahead'):
        self.main, self.releases, self.assets, self.tags, self.compare = main, list(releases), assets or {}, tags or {}, compare
        self.calls = []

    def api(self, path, method='GET', body=None, **options):
        self.calls.append((method, path, body))
        if path.endswith('/commits/main'):
            return {'sha': self.main()}
        if '/releases?' in path:
            return self.releases
        if '/releases/assets/' in path:
            return self.assets[int(path.rsplit('/', 1)[1])]
        if '/git/ref/tags/' in path:
            return {'object': self.tags[path.rsplit('/', 1)[1]]}
        if '/compare/' in path:
            return {'status': self.compare}
        if path.endswith('/dispatches'):
            return None
        raise AssertionError(path)


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / 'app'
        self.root.mkdir()
        self.git = git_fixture(self.root)
        (self.root / '.release').mkdir()
        (self.root / '.release/deploy.py').write_text(release.deploy_command('a' * 40, 'b' * 64))
        (self.root / release.WORKFLOW).parent.mkdir(parents=True)
        (self.root / release.WORKFLOW).write_text(release.TEMPLATE)
        (self.root / 'package.json').write_text('{"packageManager": "npm@12.2.0"}\n')
        (self.root / 'package-lock.json').write_text('{"vulnerable":true}\n')
        (self.root / '.gitignore').write_text('ignored/\n')
        self.git('add', '--all')
        self.git('commit', '--quiet', '-m', 'Application')
        self.artifact = Path(directory.name) / 'fix'
        self.pushed = []

    def head(self):
        return self.git('rev-parse', 'HEAD')

    def manager(self, fix):
        (self.root.parent / 'manager.py').write_text(f'''import pathlib,sys
lock = pathlib.Path('package-lock.json')
if sys.argv[1:] == ['audit']:
    sys.exit(0 if 'fixed' in lock.read_text() else 7)
assert sys.argv[1:] == ['audit', 'fix', '--package-lock-only'], sys.argv
{fix}
''')
        manager = self.root.parent / 'npm'
        manager.write_text(f'#!/bin/sh\nexec {sys.executable} {self.root.parent / "manager.py"} "$@"\n')
        manager.chmod(0o755)
        return [str(manager)]

    def fix(self, change):
        self.revision = self.head()
        gh = MaintenanceGitHub(main=lambda: self.revision)
        outputs = Path(self.root.parent / 'outputs')
        outputs.write_text('')
        with patch.object(release, 'toolchain', return_value=self.manager(change)), \
                patch.object(release, 'verify', side_effect=AssertionError('fix must not install or build')), \
                patch.object(release, 'push_main', side_effect=AssertionError('fix must not push')), \
                patch.dict(release.os.environ, {'GITHUB_OUTPUT': str(outputs)}):
            release.fix(gh, self.root, self.revision, 'owner/app', {'audit': ['audit']}, self.artifact)
        return gh, outputs.read_text()

    def apply(self, tree, revision=None):
        revision = revision or self.head()
        gh = MaintenanceGitHub(main=lambda: revision)
        with patch.object(release, 'toolchain', side_effect=AssertionError('apply-fix must not install')), \
                patch.object(release, 'run', wraps=release.run) as run, \
                patch.object(release, 'push_main', side_effect=lambda root, repository, token, commit: self.pushed.append(commit)):
            release.apply_fix(gh, self.root, revision, 'owner/app', {'audit': ['audit']}, self.artifact, tree)
        self.assertTrue(all(Path(str(call.args[0][0])).name == 'git' for call in run.call_args_list))
        return gh

    def test_a_lockfile_only_fix_is_resolved_without_credentials_then_pushed_by_a_job_that_builds_nothing(self):
        base = self.head()
        _, outputs = self.fix("lock.write_text('{\"fixed\":true}\\n')")
        tree = self.git('rev-parse', 'HEAD^{tree}')
        self.assertEqual(outputs, f'tree={tree}\n')
        self.assertEqual(self.git('log', '-1', '--format=%an <%ae>'), f'{release.BOT[0]} <{release.BOT[1]}>')
        self.assertEqual(self.git('show', '--name-only', '--format=', 'HEAD'), 'package-lock.json')
        self.assertEqual([path.name for path in self.artifact.iterdir()], ['package-lock.json'])
        # The write job starts from the same main in a fresh checkout.
        self.git('reset', '--quiet', '--hard', base)
        gh = self.apply(tree)
        self.assertEqual(self.pushed, [self.head()])
        self.assertEqual(self.git('rev-parse', 'HEAD^{tree}'), tree)
        self.assertEqual(self.git('log', '-1', '--format=%an <%ae>'), f'{release.BOT[0]} <{release.BOT[1]}>')
        self.assertIn(('POST', 'repos/owner/app/actions/workflows/web-release.yml/dispatches', {'ref': 'main'}), gh.calls)

    def test_apply_fix_refuses_artifacts_that_differ_from_the_qualified_tree_or_touch_other_paths(self):
        base = self.head()
        self.fix("lock.write_text('{\"fixed\":true}\\n')")
        tree = self.git('rev-parse', 'HEAD^{tree}')
        self.git('reset', '--quiet', '--hard', base)
        lockfile = self.artifact / 'package-lock.json'
        for prepare, qualified, message in [
                (lambda: lockfile.write_text('{"fixed":"other"}\n'), tree, 'differs from the qualified fix'),
                (lambda: lockfile.write_text('{"vulnerable":true}\n'), tree, 'does not change exactly'),
                (lambda: (self.artifact / 'package.json').write_text('{}'), tree, 'only package-lock.json'),
                (lambda: None, '', 'qualified fix tree')]:
            for path in self.artifact.iterdir():
                path.unlink()
            lockfile.write_text('{"fixed":true}\n')
            prepare()
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.apply(qualified, base)
            self.git('reset', '--quiet', '--hard', base)
        self.assertEqual(self.pushed, [])

    def test_non_lockfile_changes_and_ineffective_fixes_are_refused(self):
        for change, message in [("lock.write_text('{\"fixed\":true}\\n'); pathlib.Path('package.json').write_text('{\"x\":1}')",
                                 'more than the lockfile'),
                                ("lock.write_text('{\"fixed\":true}\\n'); pathlib.Path('new.txt').write_text('x')",
                                 'more than the lockfile'),
                                ('pass', 'No lockfile-only fix'),
                                ("lock.write_text('{\"still\":true}\\n')", 'does not satisfy the audit')]:
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, message):
                self.fix(change)
            self.git('checkout', '--quiet', '--', '.')
            self.git('clean', '--quiet', '-fd')
        self.assertFalse(self.artifact.exists())

    def test_a_passing_dependency_audit_or_a_stale_checkout_changes_nothing(self):
        (self.root / 'package-lock.json').write_text('{"fixed":true}\n')
        self.git('commit', '--quiet', '-am', 'Fixed')
        revision = self.head()
        # The failed scheduled audit was about standards, so the run stays failed.
        with self.assertRaisesRegex(ValueError, 'pass their audit'):
            self.fix('raise SystemExit(3)')
        self.assertEqual(self.head(), revision)
        gh = MaintenanceGitHub(main=lambda: 'f' * 40)
        with self.assertRaisesRegex(ValueError, 'current main'):
            release.fix(gh, self.root, self.head(), 'owner/app', {'audit': ['audit']}, self.artifact)
        self.assertFalse(self.artifact.exists())

    def publisher_release(self, ref, sha256, *, immutable=True, template=release.TEMPLATE, deploy=release.DEPLOY):
        data = json.dumps({'ref': ref, 'sha256': sha256, 'template': hashlib.sha256(template.encode()).hexdigest(),
                           'deploy': hashlib.sha256(deploy.encode()).hexdigest()}).encode()
        asset = {'id': len(ref), 'name': 'publisher.json', 'digest': 'sha256:' + hashlib.sha256(data).hexdigest()}
        return ({'tag_name': 'publisher-' + ref, 'draft': False, 'immutable': immutable, 'assets': [asset]},
                {asset['id']: data}, {'publisher-' + ref: {'type': 'commit', 'sha': ref}})

    def test_the_publisher_manifest_records_the_wiring_it_demands(self):
        manifest = json.loads(release.publisher_manifest('c' * 40, b'source'))
        self.assertEqual(manifest, {'ref': 'c' * 40, 'sha256': hashlib.sha256(b'source').hexdigest(),
                                    'template': hashlib.sha256(release.TEMPLATE.encode()).hexdigest(),
                                    'deploy': hashlib.sha256(release.DEPLOY.encode()).hexdigest()})
        self.assertEqual(release.repin(release.deploy_command('a' * 40, 'b' * 64), '{ref}', '{sha256}'), release.DEPLOY)

    def test_refresh_adopts_the_newest_immutable_descendant(self):
        source = b'new publisher'
        newest, assets, tags = self.publisher_release('c' * 40, hashlib.sha256(source).hexdigest())
        mutable = {**self.publisher_release('d' * 40, 'e' * 64)[0], 'immutable': False}
        revision = self.head()
        gh = MaintenanceGitHub(main=lambda: revision, releases=[mutable, newest], assets=assets, tags=tags)
        with patch.object(release, 'push_main', side_effect=lambda root, repository, token, commit: self.pushed.append(commit)):
            release.refresh(gh, self.root, revision, 'owner/app', fetch=lambda ref: source)
        self.assertEqual((self.root / '.release/deploy.py').read_text(),
                         release.deploy_command('c' * 40, hashlib.sha256(source).hexdigest()))
        self.assertEqual(self.pushed, [self.head()])
        self.assertEqual(self.git('show', '--name-only', '--format=', self.head()), '.release/deploy.py')
        self.assertIn(('POST', 'repos/owner/app/actions/workflows/web-release.yml/dispatches', {'ref': 'main'}), gh.calls)

    def test_refresh_leaves_template_and_deploy_command_changes_to_the_owner(self):
        source = b'new publisher'
        revision = self.head()
        for changed in [{'template': release.TEMPLATE + '# changed\n'}, {'deploy': release.DEPLOY + '# changed\n'}]:
            newest, assets, tags = self.publisher_release('c' * 40, hashlib.sha256(source).hexdigest(), **changed)
            gh = MaintenanceGitHub(main=lambda: revision, releases=[newest], assets=assets, tags=tags)
            with self.subTest(changed=list(changed)):
                with self.assertRaisesRegex(ValueError, 'Owner action needed.*adopt'):
                    release.refresh(gh, self.root, revision, 'owner/app', fetch=lambda ref: source)
                # The daily audit reports the same owner action.
                with self.assertRaisesRegex(ValueError, 'Owner action needed'):
                    release.adoptable_publisher(gh, self.root, revision, fetch=lambda ref: source)
        self.assertEqual((self.head(), self.pushed), (revision, []))
        legacy = json.dumps({'ref': 'c' * 40, 'sha256': 'e' * 64}).encode()
        newest, _, tags = self.publisher_release('c' * 40, 'e' * 64)
        newest['assets'][0]['digest'] = 'sha256:' + hashlib.sha256(legacy).hexdigest()
        gh = MaintenanceGitHub(main=lambda: revision, releases=[newest], assets={40: legacy}, tags=tags)
        with self.assertRaisesRegex(ValueError, 'wiring'):
            release.adoptable_publisher(gh, self.root, revision)

    def test_refresh_never_moves_backwards_or_trusts_a_mismatched_download(self):
        newest, assets, tags = self.publisher_release('c' * 40, 'e' * 64)
        revision = self.head()
        for compare, fetched, message in [('behind', b'x', 'does not descend'), ('ahead', b'tampered', 'checksum mismatch')]:
            gh = MaintenanceGitHub(main=lambda: revision, releases=[newest], assets=assets, tags=tags, compare=compare)
            with self.subTest(compare=compare), self.assertRaisesRegex(ValueError, message):
                release.refresh(gh, self.root, revision, 'owner/app', fetch=lambda ref: fetched)
        self.assertEqual(self.head(), revision)
        current, assets, tags = self.publisher_release('a' * 40, 'b' * 64)
        gh = MaintenanceGitHub(main=lambda: revision, releases=[current], assets=assets, tags=tags)
        release.refresh(gh, self.root, revision, 'owner/app', fetch=lambda ref: self.fail('downloaded the current publisher'))
        self.assertEqual(self.head(), revision)


class AdmissionTests(unittest.TestCase):
    def test_local_heavy_operations_queue_through_the_monorepo_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            mono = Path(directory)
            (mono / 'tools').mkdir()
            (mono / 'tools/heavy').write_text('')
            app = mono / 'apps/app'
            app.mkdir(parents=True)
            with patch.dict(release.os.environ, {}, clear=True), patch.object(release.os, 'execv') as execv, \
                    patch.object(sys, 'argv', ['release.py', '--root', str(app), 'verify']):
                release.admit(app)
            arguments = execv.call_args.args[1]
            self.assertEqual(arguments[1:5], [str(mono / 'tools/heavy'), '--budget', '7200', '--'])
            self.assertEqual(arguments[-3:], ['--root', str(app), 'verify'])
            for environment in [{'HEAVY_ADMITTED': '1'}, {'GITHUB_ACTIONS': 'true'}]:
                with patch.dict(release.os.environ, environment, clear=True), \
                        patch.object(release.os, 'execv', side_effect=AssertionError('queued twice')):
                    release.admit(app)
        with tempfile.TemporaryDirectory() as elsewhere, patch.dict(release.os.environ, {}, clear=True), \
                patch.object(release.os, 'execv', side_effect=AssertionError('ran without admission')), \
                self.assertRaisesRegex(ValueError, 'tools/heavy'):
            release.admit(Path(elsewhere) / 'app')


class BaseImageTests(unittest.TestCase):
    def test_refresh_selects_the_newest_cooled_down_patch_of_the_pinned_line(self):
        now = datetime(2026, 11, 7, tzinfo=timezone.utc)
        base = 'docker.io/library/nginx:1.30.6-alpine-slim@sha256:' + 'a' * 64
        def tag(name, digest, days):
            return {'name': name, 'digest': 'sha256:' + digest * 64,
                    'tag_last_pushed': (now - timedelta(days=days)).isoformat().replace('+00:00', 'Z')}
        tags = [tag('1.30.7-alpine-slim', 'b', 8), tag('1.30.8-alpine-slim', 'c', 2), tag('1.31.0-alpine-slim', 'd', 30),
                tag('1.30.9-alpine', 'e', 30), tag('1.30.5-alpine-slim', 'f', 30)]
        self.assertEqual(release.base_candidate(tags, now, base),
                         'docker.io/library/nginx:1.30.7-alpine-slim@sha256:' + 'b' * 64)
        self.assertIsNone(release.base_candidate([tag('1.30.6-alpine-slim', 'a', 9)], now, base))
        self.assertIsNone(release.base_candidate([tag('1.30.6-alpine-slim', 'b', 3), tag('1.30.5-alpine-slim', 'c', 30)], now, base))
        self.assertEqual(release.base_candidate([tag('1.30.6-alpine-slim', 'b', 7)], now, base),
                         'docker.io/library/nginx:1.30.6-alpine-slim@sha256:' + 'b' * 64)

    def test_a_base_refresh_is_qualified_without_write_credentials_and_committed_by_a_job_that_scans_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git = git_fixture(root)
            (root / 'release.py').write_text(Path(release.__file__).read_text())
            git('add', '--all')
            git('commit', '--quiet', '-m', 'Publisher')
            pinned = re.fullmatch(r'(docker\.io/library/nginx:\d+\.\d+\.)(\d+)(-alpine-slim@sha256:)[a-f0-9]{64}', release.BASE)
            newer = pinned.group(1) + str(int(pinned.group(2)) + 1) + pinned.group(3) + 'c' * 64
            revision = git('rev-parse', 'HEAD')
            for candidate in ['', release.BASE, pinned.group(1) + str(int(pinned.group(2)) - 1) + pinned.group(3) + 'c' * 64,
                              'docker.io/library/nginx:9.9.9-alpine-slim@sha256:' + 'c' * 64,
                              'docker.io/evil/nginx' + newer.removeprefix('docker.io/library/nginx'), newer + '\nBASE = 1']:
                with self.subTest(candidate=candidate), self.assertRaisesRegex(ValueError, 'newer digest'):
                    release.apply_base(MaintenanceGitHub(main=lambda: revision), root, candidate)
            pushed = []
            gh = MaintenanceGitHub(main=lambda: revision)
            with patch.object(release, 'scan_base', side_effect=AssertionError('apply-base must not scan')), \
                    patch.object(release, 'push_main', side_effect=lambda root, repository, token, commit: pushed.append((repository, commit))):
                release.apply_base(gh, root, newer)
            self.assertEqual(pushed, [(release.PUBLISHER, git('rev-parse', 'HEAD'))])
            self.assertEqual(git('show', '--name-only', '--format=', 'HEAD'), 'release.py')
            self.assertIn(f"\nBASE = '{newer}'\n", (root / 'release.py').read_text())
            self.assertIn(('POST', f'repos/{release.PUBLISHER}/actions/workflows/ci.yml/dispatches', {'ref': 'main'}), gh.calls)

    def test_the_template_is_the_only_release_workflow_and_calls_only_the_deploy_command(self):
        commands = re.findall(r'^\s+run: (.*)$', release.TEMPLATE, re.M)
        self.assertEqual({command.split()[2] for command in commands},
                         {'status', 'verify', 'publish', 'refresh', 'audit', 'fix', 'apply-fix'})
        self.assertTrue(all(command.startswith('python3 .release/deploy.py ') for command in commands))
        self.assertNotIn(release.LEGACY_CALLER, release.TEMPLATE)

    def test_write_tokens_never_share_a_job_with_installs_builds_or_dependency_code(self):
        for workflow in [release.TEMPLATE, *(Path(release.__file__).parent / '.github/workflows').glob('*.yml')]:
            text = workflow if isinstance(workflow, str) else workflow.read_text()
            jobs = re.split(r'^  (?=[\w-]+:\n)', text.split('\njobs:\n', 1)[1], flags=re.M)[1:]
            for job in jobs:
                name = job.split(':', 1)[0]
                commands = re.findall(r'run: python3 (?:\.release/deploy|release)\.py (\S+)', job)
                with self.subTest(job=name):
                    if re.search(r'^      \w+: write$', job, re.M):
                        self.assertNotRegex(job, 'setup-node|setup-uv|actions/cache|submodules|unittest')
                        self.assertLessEqual(set(commands), {'publish', 'apply-fix', 'refresh', 'apply-base'})
                    else:
                        self.assertFalse(set(commands) & {'publish', 'apply-fix', 'refresh', 'apply-base'})


if __name__ == '__main__':
    unittest.main()
