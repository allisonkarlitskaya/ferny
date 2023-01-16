import glob
import os
import unittest
import shutil
import tempfile

import mockssh

import ferny

os.environ.pop('SSH_AUTH_SOCK', None)
os.environ.pop('SSH_ASKPASS', None)


class MockAskpass(ferny.Askpass):
    async def askpass(self, msg, hint):
        if 'fingerprint' in msg:
            return 'yes'
        else:
            return 'passphrase'


class TestBasic(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(kls):
        # git does not track file permissions, and SSH fails on group/world readability
        kls.key_dir = tempfile.TemporaryDirectory(prefix='ferny-test-keys.')
        # copy all test/id_* files to the temporary directory with 0600 permissions
        for key in glob.glob('test/id_*'):
            dest = os.path.join(kls.key_dir.name, os.path.basename(key))
            shutil.copy(key, dest)
            os.chmod(dest, 0o600)

        kls.runtime_dir = tempfile.TemporaryDirectory(prefix='ferny-test-run.')
        os.environ['XDG_RUNTIME_DIR'] = kls.runtime_dir.name

    async def test_rsa_key(self):
        users = {'admin': 'test/id_rsa'}
        with mockssh.Server(users) as server:
            session = ferny.Session()
            await session.connect(server.host,
                                  port=server.port,
                                  configfile='none',
                                  options={
                                      'UserKnownHostsFile': '/dev/null',
                                      'StrictHostKeyChecking': 'no'
                                  },
                                  identity_file=os.path.join(self.key_dir.name, 'id_rsa.enc'),
                                  login_name='admin',
                                  askpass_factory=MockAskpass)
            await session.disconnect()
            assert os.listdir(self.runtime_dir.name) == []
