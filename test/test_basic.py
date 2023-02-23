import glob
import os
import unittest
import shutil
import tempfile

import mockssh
import pytest

import ferny

os.environ.pop('SSH_AUTH_SOCK', None)
os.environ.pop('SSH_ASKPASS', None)


class MockResponder(ferny.InteractionResponder):
    async def do_askpass(self, messages, prompt, hint):
        assert 'passphrase' in prompt
        if isinstance(self.passphrase, Exception):
            raise self.passphrase
        return self.passphrase

    async def do_hostkey(self, reason, host, algorithm, key, fingerprint):
        print('host key', host, algorithm, key, fingerprint)
        if isinstance(self.accept_hostkey, Exception):
            raise self.accept_hostkey
        return self.accept_hostkey

    def __init__(self, accept_hostkey, passphrase):
        self.accept_hostkey = accept_hostkey
        self.passphrase = passphrase


# these both come from mockssh and aren't interesting to us
@pytest.mark.filterwarnings('ignore:.*setDaemon.* is deprecated:DeprecationWarning')
@pytest.mark.filterwarnings('ignore::pytest.PytestUnhandledThreadExceptionWarning')
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

    async def run_test(self, accept_hostkey, passphrase):
        responder = MockResponder(accept_hostkey, passphrase)
        users = {'admin': 'test/id_rsa'}
        with mockssh.Server(users) as server:
            session = ferny.Session()
            await session.connect(server.host,
                                  port=server.port,
                                  configfile='none',
                                  handle_host_key=True,
                                  identity_file=os.path.join(self.key_dir.name, 'id_rsa.enc'),
                                  login_name='admin', interaction_responder=responder)
            assert os.listdir(self.runtime_dir.name) == []
            await session.disconnect()

    async def test_reject_hostkey(self):
        with self.assertRaises(ferny.SshError) as raises:
            await self.run_test(False, FloatingPointError())
        assert str(raises.exception) == 'Host key verification failed.'

    async def test_raise_hostkey(self):
        with self.assertRaises(ZeroDivisionError):
            await self.run_test(ZeroDivisionError(), FloatingPointError())

    async def test_raise_passphrase(self):
        with self.assertRaises(FloatingPointError):
            await self.run_test(True, FloatingPointError())

    async def test_wrong_passphrase(self):
        with self.assertRaises(ferny.SshError) as raises:
            await self.run_test(True, 'xx')
        assert 'Permission denied' in str(raises.exception)

    async def test_correct_passphrase(self):
        await self.run_test(True, 'passphrase')
