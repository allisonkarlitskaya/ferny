import glob
import os
import shutil
import socket
import tempfile

import mockssh
import pytest

import ferny

os.environ.pop('SSH_AUTH_SOCK', None)
os.environ.pop('SSH_ASKPASS', None)


class MockResponder(ferny.InteractionResponder):
    async def do_askpass(self, messages, prompt, hint):
        if 'fingerprint' in prompt:
            return 'yes' if await self.do_hostkey(0, 0, 0, 0, 0) else 'no'
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


@pytest.fixture(scope='class')
def key_dir():
    # git does not track file permissions, and SSH fails on group/world readability
    _key_dir = tempfile.TemporaryDirectory(prefix='ferny-test-keys.')
    # copy all test/id_* files to the temporary directory with 0600 permissions
    for key in glob.glob('test/id_*'):
        dest = os.path.join(_key_dir.name, os.path.basename(key))
        shutil.copy(key, dest)
        os.chmod(dest, 0o600)

    return _key_dir


@pytest.fixture()
def runtime_dir():
    d = tempfile.TemporaryDirectory(prefix='ferny-test-run.')
    os.environ['XDG_RUNTIME_DIR'] = d.name
    return d


def test_feature_detection():
    # should be case-insensitive, and pass
    assert ferny.session.has_feature('userknownhostsfile')
    assert ferny.session.has_feature('UserKnownHostsFile')

    # yummy, but probably never exists
    assert not ferny.session.has_feature('usersconehostsfile')
    assert not ferny.session.has_feature('UserSconeHostsFile')

    # requires a specific value
    assert not ferny.session.has_feature('StrictHostKeyChecking')
    assert ferny.session.has_feature('StrictHostKeyChecking', 'yes')


@pytest.mark.asyncio
async def test_connection_refused():
    session = ferny.Session()
    with pytest.raises(ConnectionRefusedError):
        # hopefully nobody listens on 1...
        await session.connect('127.0.0.1', port=1)


@pytest.mark.asyncio
async def test_dns_error():
    session = ferny.Session()
    with pytest.raises(socket.gaierror):
        await session.connect('¡invalid hostname!')


# these both come from mockssh and aren't interesting to us
@pytest.mark.filterwarnings('ignore:.*setDaemon.* is deprecated:DeprecationWarning')
@pytest.mark.filterwarnings('ignore::pytest.PytestUnhandledThreadExceptionWarning')
@pytest.mark.filterwarnings('ignore::cryptography.utils.CryptographyDeprecationWarning')
class TestBasic:
    @staticmethod
    async def run_test(key_dir, runtime_dir, accept_hostkey, passphrase):
        responder = MockResponder(accept_hostkey, passphrase)
        users = {'admin': 'test/id_rsa'}
        with mockssh.Server(users) as server:
            session = ferny.Session()
            await session.connect(server.host,
                                  port=server.port,
                                  configfile='none',
                                  handle_host_key=True,
                                  identity_file=os.path.join(key_dir.name, 'id_rsa.enc'),
                                  login_name='admin',
                                  options=dict(userknownhostsfile="/dev/null"),
                                  interaction_responder=responder)
            assert os.listdir(runtime_dir.name) == []
            await session.disconnect()

    @pytest.mark.asyncio
    async def test_reject_hostkey(self, key_dir, runtime_dir):
        with pytest.raises(ferny.HostKeyError) as raises:
            await self.run_test(key_dir, runtime_dir, False, FloatingPointError())
        assert str(raises.value) == 'Host key verification failed.'

    @pytest.mark.asyncio
    async def test_raise_hostkey(self, key_dir, runtime_dir):
        with pytest.raises(ZeroDivisionError):
            await self.run_test(key_dir, runtime_dir, ZeroDivisionError(), FloatingPointError())

    @pytest.mark.asyncio
    async def test_raise_passphrase(self, key_dir, runtime_dir):
        with pytest.raises(FloatingPointError):
            await self.run_test(key_dir, runtime_dir, True, FloatingPointError())

    @pytest.mark.asyncio
    async def test_wrong_passphrase(self, key_dir, runtime_dir):
        with pytest.raises(ferny.AuthenticationError) as raises:
            await self.run_test(key_dir, runtime_dir, True, 'xx')
        assert 'Permission denied' in str(raises.value)
        assert 'publickey' in raises.value.methods

    @pytest.mark.asyncio
    async def test_correct_passphrase(self, key_dir, runtime_dir):
        await self.run_test(key_dir, runtime_dir, True, 'passphrase')

    @pytest.mark.asyncio
    async def test_large_env(self, key_dir, runtime_dir):
        orig = os.environ.copy()
        os.environ['BLABBERMOUTH'] = 'bla' * 10000
        try:
            await self.run_test(key_dir, runtime_dir, True, 'passphrase')
        finally:
            os.environ = orig
