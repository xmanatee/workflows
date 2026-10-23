import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import urllib.request
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


if __name__ == '__main__':
    unittest.main()
