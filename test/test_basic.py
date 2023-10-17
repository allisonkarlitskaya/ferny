import glob
import os
import pathlib
import shutil
import socket
import subprocess

import mockssh
import pytest

import ferny

os.environ.pop('SSH_AUTH_SOCK', None)
os.environ.pop('SSH_ASKPASS', None)

# some host key which isn't the one from mock-ssh
NONMATCHING_HOSTKEY = (
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDWdxkgPs4niiaW41P8NiKjI3slCoeaRQvvchTHCyvQMGOanv+iudgurkc' +
    'VvJOWOHsbLdxSfW5KbF1bGpVu3nwjbA7rajDx8Xs4z6VLsd4WCrHJl0qZt5GFfYTriIiPfE1t/C9MIxA1Vfxz099DBQDgs9' +
    '6kt7EidP2cBTb1rWGjBAt71jlfuxH4g1+emuPcuhdY3PFH5Ac7IwG5So3jxUWB7esDiO7StoKcAU2iJzp8yFLOrekYn8IA9' +
    'cAxyzgYzlnqs8S/6aFrm/xTYAb1YIGyLUoyQgAIQW4MlILxq5opS3+YUYZaBLZRYoI2vkqqF+ULeqdZzgcOSLe4cbE3bZql')


class MockResponder(ferny.SshAskpassResponder):
    passphrase: 'Exception | str | None'
    accept_hostkey: 'Exception | bool'
    askpass_args: 'list[tuple[str, str, str]]'
    hostkey_args: 'list[tuple[str, str, str, str, str]]'

    def __init__(self, accept_hostkey: 'Exception | bool', passphrase: 'Exception | str | None') -> None:
        self.accept_hostkey = accept_hostkey
        self.passphrase = passphrase
        # reset the mock state on each iteration
        MockResponder.askpass_args = []
        MockResponder.hostkey_args = []

    async def do_askpass(self, messages: str, prompt: str, hint: str) -> 'str | None':
        # this happens on RHEL 8 which doesn't have KnownHostKey support; and everywhere with
        # handle_host_key=False, then this callback receives *every* agent interaction
        if 'fingerprint' in prompt:
            return 'yes' if await self.do_hostkey('', '', '', '', '') else 'no'
        assert 'passphrase' in prompt
        self.askpass_args.append((messages, prompt, hint))
        if isinstance(self.passphrase, Exception):
            raise self.passphrase
        return self.passphrase

    async def do_hostkey(self, reason: str, host: str, algorithm: str, key: str, fingerprint: str) -> bool:
        self.hostkey_args.append((reason, host, algorithm, key, fingerprint))
        if isinstance(self.accept_hostkey, Exception):
            raise self.accept_hostkey
        return self.accept_hostkey


@pytest.fixture
def key_dir(tmp_path: pathlib.Path, pytestconfig: pytest.Config) -> pathlib.Path:
    # git does not track file permissions, and SSH fails on group/world readability
    # copy all test/id_* files to the temporary directory with 0600 permissions
    keydir = tmp_path / 'keys'
    keydir.mkdir()
    for key in glob.glob(f'{pytestconfig.rootpath}/test/id_*'):
        dest = keydir / os.path.basename(key)
        shutil.copy(key, dest)
        os.chmod(dest, 0o600)

    return keydir


@pytest.fixture()
def runtime_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> pathlib.Path:
    rundir = tmp_path / 'xdg-run'
    rundir.mkdir()
    monkeypatch.setenv('XDG_RUNTIME_DIR', str(rundir))
    return rundir


def test_feature_detection() -> None:
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
async def test_connection_refused(runtime_dir: pathlib.Path) -> None:
    del runtime_dir
    session = ferny.Session()
    with pytest.raises(ConnectionRefusedError):
        # hopefully nobody listens on 1...
        await session.connect('127.0.0.1', port=1)


@pytest.mark.asyncio
async def test_dns_error(runtime_dir: pathlib.Path) -> None:
    session = ferny.Session()
    with pytest.raises(socket.gaierror):
        await session.connect('¡invalid hostname!')


# these both come from mockssh and aren't interesting to us
@pytest.mark.filterwarnings('ignore:.*setDaemon.* is deprecated:DeprecationWarning')
@pytest.mark.filterwarnings('ignore::pytest.PytestUnhandledThreadExceptionWarning')
@pytest.mark.filterwarnings('ignore::cryptography.utils.CryptographyDeprecationWarning')
class TestBasic:
    @staticmethod
    async def run_test(
        key_dir: pathlib.Path,
        runtime_dir: pathlib.Path,
        accept_hostkey: 'Exception | bool',
        passphrase: 'Exception | str',
        known_host_key: 'str | None' = None,
        handle_host_key: bool = False,
    ) -> None:
        responder = MockResponder(accept_hostkey, passphrase)
        users = {'admin': 'test/id_rsa'}
        known_hosts = key_dir / 'known_hosts'

        with mockssh.Server(users) as server:
            if known_host_key == 'scan':
                known_host_key = subprocess.check_output(['ssh-keyscan', '-p', str(server.port), '127.0.0.1'],
                                                         universal_newlines=True)
                known_hosts.write_text(known_host_key)
            elif known_host_key:
                known_hosts.write_text(f'[127.0.0.1]:{server.port} {known_host_key}')

            session = ferny.Session()
            await session.connect(
                server.host,
                port=server.port,
                configfile='none',
                handle_host_key=handle_host_key,
                identity_file=os.path.join(key_dir, 'id_rsa.enc'),
                login_name='admin',
                options=dict(userknownhostsfile=str(known_hosts)),
                interaction_responder=responder)

            # if we get that far, we have successfully authenticated
            p = subprocess.run(session.wrap_subprocess_args(['sh', '-ec', 'echo dmcetomer | rev']),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            assert p.stdout == b'remotecmd\n'
            assert p.stderr == b''

            assert os.listdir(runtime_dir) == ['ferny']
            await session.disconnect()

    #
    # with handling host keys
    #

    @pytest.mark.asyncio
    async def test_reject_hostkey(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        with pytest.raises(ferny.HostKeyError) as raises:
            await self.run_test(key_dir, runtime_dir, False, FloatingPointError(), handle_host_key=True)

        # got one host key request with a sensible RSA key
        assert MockResponder.askpass_args == []
        assert len(MockResponder.hostkey_args) == 1
        reason, host, algorithm, key, fingerprint = MockResponder.hostkey_args[0]

        if ferny.session.has_feature('KnownHostsCommand'):
            # on modern OSes we get a specific error message
            assert isinstance(raises.value, ferny.UnknownHostKeyError)
            assert 'No RSA host key is known for [127.0.0.1]:' in str(raises.value)
            assert 'Host key verification failed.' in str(raises.value)
            assert reason == 'HOSTNAME'
            assert host.startswith('[127.0.0.1]:')  # plus random port
            assert algorithm == 'ssh-rsa'
            assert key.startswith('AAAA')
            assert fingerprint.startswith('SHA256:')  # depends on mock-ssh implementation
        else:
            # on old OSes we only get a generic error
            assert str(raises.value) == 'Host key verification failed.'
            # ... and dummy values from MockResponder
            assert reason == ''
            assert key == ''

    @pytest.mark.asyncio
    async def test_raise_hostkey(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        with pytest.raises(ZeroDivisionError):
            await self.run_test(key_dir, runtime_dir, ZeroDivisionError(), FloatingPointError(), handle_host_key=True)

    @pytest.mark.asyncio
    async def test_raise_passphrase(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        with pytest.raises(FloatingPointError):
            await self.run_test(key_dir, runtime_dir, True, FloatingPointError(), handle_host_key=True)

    @pytest.mark.asyncio
    async def test_wrong_passphrase(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        with pytest.raises(ferny.AuthenticationError) as raises:
            await self.run_test(key_dir, runtime_dir, True, 'xx', handle_host_key=True)
        assert 'Permission denied' in str(raises.value)
        assert 'publickey' in raises.value.methods
        assert len(MockResponder.hostkey_args) == 1
        assert len(MockResponder.askpass_args) == 3  # default NumberOfPasswordPrompts
        _messages, prompt, hint = MockResponder.askpass_args[0]
        assert 'Enter passphrase for key' in prompt
        assert 'keys/id_rsa.enc' in prompt

    @pytest.mark.asyncio
    async def test_correct_passphrase(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        await self.run_test(key_dir, runtime_dir, True, 'passphrase', handle_host_key=True)
        assert len(MockResponder.hostkey_args) == 1
        assert len(MockResponder.askpass_args) == 1
        _messages, prompt, hint = MockResponder.askpass_args[0]
        assert 'Enter passphrase for key' in prompt
        assert 'keys/id_rsa.enc' in prompt

    @pytest.mark.asyncio
    async def test_known_host_good(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        # this calls do_hostkey() for the already known key, just in case it wants to supply additional keys
        # don't do this and don't accept any, just rely on the existing one
        await self.run_test(key_dir, runtime_dir, False, 'passphrase',
                            handle_host_key=True, known_host_key='scan')

    @pytest.mark.asyncio
    async def test_known_host_changed(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        # reject new host key
        with pytest.raises(ferny.ChangedHostKeyError) as raises:
            await self.run_test(key_dir, runtime_dir, False, 'passphrase',
                                handle_host_key=True, known_host_key=NONMATCHING_HOSTKEY)
        assert 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED' in str(raises.value)

        # accept new host key
        if ferny.session.has_feature('KnownHostsCommand'):
            await self.run_test(key_dir, runtime_dir, True, 'passphrase',
                                handle_host_key=True, known_host_key=NONMATCHING_HOSTKEY)
        else:
            # without KnownHostsCommand, we can't prompt
            with pytest.raises(ferny.ChangedHostKeyError) as raises:
                await self.run_test(key_dir, runtime_dir, True, 'passphrase',
                                    handle_host_key=True, known_host_key=NONMATCHING_HOSTKEY)
            assert 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED' in str(raises.value)

    #
    # without handling host keys
    #

    @pytest.mark.asyncio
    async def test_no_host_key_unknown(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        # note we only get a generic HostKeyError here, not Unknown*, as we don't enable KnownHostsCommand
        with pytest.raises(ferny.HostKeyError) as raises:
            await self.run_test(key_dir, runtime_dir, False, 'passphrase',
                                handle_host_key=False)
        assert str(raises.value) == 'Host key verification failed.'
        assert len(MockResponder.hostkey_args) == 1
        assert len(MockResponder.askpass_args) == 0

    @pytest.mark.asyncio
    async def test_no_host_key_known(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        await self.run_test(key_dir, runtime_dir, ZeroDivisionError(), 'passphrase',
                            handle_host_key=False, known_host_key='scan')
        assert len(MockResponder.hostkey_args) == 0
        assert len(MockResponder.askpass_args) == 1

    @pytest.mark.asyncio
    async def test_no_host_key_changed(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        with pytest.raises(ferny.ChangedHostKeyError) as raises:
            await self.run_test(key_dir, runtime_dir, ZeroDivisionError(), 'passphrase',
                                handle_host_key=False, known_host_key=NONMATCHING_HOSTKEY)
        assert 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED' in str(raises.value)
        # FIXME: we don't currently prompt in this case, although we eventually should
        assert len(MockResponder.hostkey_args) == 0
        assert len(MockResponder.askpass_args) == 0

    #
    # host key independent tests
    #

    @pytest.mark.asyncio
    async def test_large_env(
        self, key_dir: pathlib.Path, runtime_dir: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv('BLABBERMOUTH', 'bla' * 10000)
        await self.run_test(key_dir, runtime_dir, True, 'passphrase')
