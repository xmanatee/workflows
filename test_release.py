import hashlib
import io
import json
from pathlib import Path
import tarfile
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
        manifest = {'repository': 'owner/app', 'revision': revision,
                    'images': {'app': 'ghcr.io/owner/app@sha256:' + 'b' * 64},
                    'qualification': {'policy': release.POLICY, 'platform': 'linux/amd64',
                                      'sourceChecks': True, 'runtimeSmoke': True, 'vulnerabilityScan': True}}
        data = json.dumps(manifest).encode()
        metadata = {'draft': False, 'immutable': True, 'html_url': 'https://example.invalid/release',
                    'assets': [{'id': 1, 'name': 'release.json',
                                'digest': 'sha256:' + hashlib.sha256(data).hexdigest()}]}
        gh = FakeGitHub()
        ref = {'object': {'type': 'commit', 'sha': revision, 'url': 'https://example.invalid/commit'}}
        with patch.object(gh, 'api', side_effect=[metadata, ref, data]) as api:
            self.assertTrue(release.completed(gh, 'owner/app', revision, {'image': 'ghcr.io/owner/app'}))
            self.assertEqual(api.call_count, 3)
        with patch.object(gh, 'api', side_effect=[metadata, {'object': {'type': 'commit', 'sha': 'wrong'}}]):
            with self.assertRaisesRegex(ValueError, 'tag does not point'):
                release.completed(gh, 'owner/app', revision, {'image': 'ghcr.io/owner/app'})

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


CONFIG = {'dist': 'dist', 'beforeBuild': [['audit']]}
NGINX = 'add_header Content-Security-Policy "script-src \'self\'; connect-src \'self\' https://api.example.org";'


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
        self.write('dist/index.html', '<script src="/assets/a.js"></script><link rel="stylesheet" href="/a.css">')
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
        release.conform(self.root, CONFIG)

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
        self.assertEqual(release.conform_scripts(self.root, CONFIG), [])

    def test_package_manager_toolchain_and_cooldown(self):
        self.write('pnpm-lock.yaml', '')
        (self.root / '.nvmrc').unlink()
        (self.root / '.npmrc').write_text('min-release-age=0\n')
        self.assertEqual(len(release.conform_package(self.root, self.root, CONFIG)), 3)
        self.write('package.json', json.dumps({'packageManager': 'npm@12', 'scripts': {}}))
        self.assertTrue(release.conform_package(self.root, self.root, CONFIG)[-1].startswith('Pin exactly one'))

    def test_pnpm_cooldown_and_private_workspace_packages(self):
        self.write('package.json', json.dumps({'private': True, 'packageManager': 'pnpm@10.34.7', 'scripts': {}}))
        (self.root / 'package-lock.json').rename(self.root / 'pnpm-lock.yaml')
        self.write('packages/a/package.json', '{}')
        self.write('pnpm-workspace.yaml', 'minimumReleaseAge: 10080\n')
        self.assertEqual(release.conform_package(self.root, self.root, CONFIG), ['packages/a/package.json must declare private: true'])
        (self.root / 'pnpm-workspace.yaml').unlink()
        self.write('packages/a/package.json', '{"private": true}')
        self.assertEqual(len(release.conform_package(self.root, self.root, CONFIG)), 1)
        self.write('.npmrc', 'minimum-release-age=10080\n')
        self.assertEqual(release.conform_package(self.root, self.root, CONFIG), [])

    def test_audit_gate_and_scheduled_heavy_workflows(self):
        self.assertEqual(len(release.conform_release({})), 1)
        self.assertEqual(release.conform_release({'beforeBuild': [['exec', 'node', 'scripts/audit-dependencies.mjs']]}), [])
        self.write('.github/workflows/nightly.yml', 'on:\n  schedule:\n    - cron: "0 3 * * *"\njobs:\n  x:\n    run: npm run check:all\n')
        self.assertEqual(len(release.conform_workflows(self.root)), 1)
        self.write('.github/workflows/nightly.yml', 'on:\n  schedule:\n    - cron: "0 3 * * *"\njobs:\n  x:\n    run: npm audit\n')
        self.assertEqual(release.conform_workflows(self.root), [])

    def test_bundle_rejects_telemetry_and_external_assets_but_not_a_mentioned_url(self):
        self.write('dist/assets/b.js', 'a="https://o1.ingest.sentry.io/1";b="https://docs.example.net/p"')
        self.write('dist/index.html', '<link rel="stylesheet" href="https://fonts.googleapis.com/css"><script src="//cdn.test/x.js"></script>')
        issues = '\n'.join(release.conform_bundle(self.root, CONFIG))
        for expected in ('sentry.io', 'fonts.googleapis.com', '//cdn.test/x.js'):
            self.assertIn(expected, issues)
        for mentioned in ('www.w3.org', 'api.example.org', 'docs.example.net'):
            self.assertNotIn(mentioned, issues)

    def test_nginx_policy_names_each_origin(self):
        self.assertEqual(release.conform_nginx(self.root), [])
        for source in ('https:', 'wss:', '*', 'https://*'):
            with self.subTest(source=source):
                self.write('nginx.conf', f'add_header Content-Security-Policy "script-src \'self\' \'unsafe-inline\'; connect-src \'self\' data: {source}";')
                self.assertEqual(release.conform_nginx(self.root), [f'nginx.conf connect-src allows the whole scheme or wildcard {source}'])
        self.write('nginx.conf', 'add_header Content-Security-Policy "connect-src \'self\' wss://other.test";')
        self.assertEqual(release.conform_nginx(self.root), ['nginx.conf needs a Content-Security-Policy with script-src'])
        self.write('nginx.conf', 'server {}')
        self.assertEqual(len(release.conform_nginx(self.root)), 2)


if __name__ == '__main__':
    unittest.main()
