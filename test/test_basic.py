import asyncio
import glob
import os
import pathlib
import shutil
import socket
from typing import Sequence

import asyncssh
import pytest

import ferny

os.environ.pop('SSH_AUTH_SOCK', None)
os.environ.pop('SSH_ASKPASS', None)


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
    for key in glob.glob(f'{pytestconfig.rootpath}/test/keys/*'):
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
async def test_invalid_hostname_error(runtime_dir: pathlib.Path) -> None:
    session = ferny.Session()
    # OpenSSH 0.9.6+ statically checks the name, earlier versions throw anything at the DNS resolver
    with pytest.raises((socket.gaierror, ferny.ssh_errors.SshInvalidHostnameError)):
        await session.connect('¡invalid hostname!')


@pytest.mark.asyncio
async def test_dns_error(runtime_dir: pathlib.Path) -> None:
    session = ferny.Session()
    # this is a validly formatted hostname
    with pytest.raises(socket.gaierror):
        await session.connect('nonexisting.local')


class MySSHServer(asyncssh.SSHServer):
    connection: 'asyncssh.SSHServerConnection | None' = None

    def connection_made(self, connection: asyncssh.SSHServerConnection) -> None:
        self.connection = connection

    def password_auth_supported(self) -> bool:
        return False

    def begin_auth(self, username: str) -> bool:
        assert self.connection is not None
        self.connection.set_authorized_keys(f'test/users/{username}.authorized_keys')
        return True

    def validate_password(self, username: str, password: str) -> bool:
        try:
            with open(f'test/users/{username}.passwd') as file:
                return password == file.read().strip()
        except FileNotFoundError:
            return False


def handle_client(process: asyncssh.SSHServerProcess) -> None:
    process.stdout.write('remotecmd\n')
    process.exit(0)


async def ssh_server() -> asyncssh.SSHAcceptor:
    return await asyncssh.listen('127.0.0.1', 0,
                                 server_host_keys=['test/keys/hostkey_ed25519', 'test/keys/hostkey_rsa'],
                                 server_factory=MySSHServer, process_factory=handle_client)


class TestBasic:
    @staticmethod
    async def run_test(
        key_dir: pathlib.Path,
        runtime_dir: pathlib.Path,
        accept_hostkey: 'Exception | bool',
        passphrase: 'Exception | str',
        known_host_keys: Sequence[str] = ('hostkey_ed25519.pub', 'hostkey_rsa.pub'),
        handle_host_key: bool = False,
    ) -> None:
        responder = MockResponder(accept_hostkey, passphrase)
        known_hosts = key_dir / 'known_hosts'

        async with await ssh_server() as server:
            host, port = server.sockets[0].getsockname()
            hostkeys = []
            for filename in known_host_keys:
                key = (key_dir / filename).read_text()
                hostkeys.append(f'[{host}]:{port} {key}\n')
            known_hosts.write_text(''.join(hostkeys))

            session = ferny.Session()
            await session.connect(
                host,
                port=port,
                configfile='none',
                handle_host_key=handle_host_key,
                identity_file=os.path.join(key_dir, 'id_ed25519_passphrase'),
                login_name='admin',
                options=dict(userknownhostsfile=str(known_hosts)),
                interaction_responder=responder)

            # if we get that far, we have successfully authenticated
            wrapped = session.wrap_subprocess_args(['echo', 'remotecmd'])
            proc = await asyncio.create_subprocess_exec(*wrapped,
                                                        stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            assert stdout == b'remotecmd\n'
            assert stderr == b''

            assert os.listdir(runtime_dir) == ['ferny']
            await session.disconnect()

    #
    # with handling host keys
    #

    @pytest.mark.asyncio
    async def test_reject_hostkey(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        with pytest.raises(ferny.SshHostKeyError) as raises:
            await self.run_test(key_dir, runtime_dir, False, FloatingPointError(),
                                handle_host_key=True, known_host_keys=())

        # got one host key request with a sensible RSA key
        assert MockResponder.askpass_args == []
        assert len(MockResponder.hostkey_args) == 1
        reason, host, algorithm, key, fingerprint = MockResponder.hostkey_args[0]

        if ferny.session.has_feature('KnownHostsCommand'):
            # on modern OSes we get a specific error message
            assert isinstance(raises.value, ferny.SshUnknownHostKeyError)
            assert 'No ED25519 host key is known for [127.0.0.1]:' in str(raises.value)
            assert 'Host key verification failed.' in str(raises.value)
            assert reason == 'HOSTNAME'
            assert host.startswith('[127.0.0.1]:')  # plus random port
            assert algorithm == 'ssh-ed25519'
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
            await self.run_test(key_dir, runtime_dir, ZeroDivisionError(), FloatingPointError(),
                                known_host_keys=(), handle_host_key=True)

    @pytest.mark.asyncio
    async def test_raise_passphrase(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        with pytest.raises(FloatingPointError):
            await self.run_test(key_dir, runtime_dir, True, FloatingPointError(), handle_host_key=True)

    @pytest.mark.asyncio
    async def test_wrong_passphrase(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        with pytest.raises(ferny.SshAuthenticationError) as raises:
            await self.run_test(key_dir, runtime_dir, True, 'xx', known_host_keys=(), handle_host_key=True)
        assert 'Permission denied' in str(raises.value)
        assert 'publickey' in raises.value.methods
        assert len(MockResponder.hostkey_args) == 1
        assert len(MockResponder.askpass_args) == 3  # default NumberOfPasswordPrompts
        _messages, prompt, hint = MockResponder.askpass_args[0]
        assert 'Enter passphrase for key' in prompt
        assert 'keys/id_ed25519_passphrase' in prompt

    @pytest.mark.asyncio
    async def test_correct_passphrase(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        await self.run_test(key_dir, runtime_dir, True, 'passphrase', known_host_keys=(), handle_host_key=True)
        assert len(MockResponder.hostkey_args) == 1
        assert len(MockResponder.askpass_args) == 1
        _messages, prompt, hint = MockResponder.askpass_args[0]
        assert 'Enter passphrase for key' in prompt
        assert 'keys/id_ed25519_passphrase' in prompt

    @pytest.mark.asyncio
    async def test_known_host_good(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        # this calls do_hostkey() for the already known key, just in case it wants to supply additional keys
        # don't do this and don't accept any, just rely on the existing one
        await self.run_test(key_dir, runtime_dir, False, 'passphrase',
                            handle_host_key=True)

    @pytest.mark.asyncio
    async def test_known_host_changed(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        # reject new host key
        with pytest.raises(ferny.SshChangedHostKeyError) as raises:
            await self.run_test(key_dir, runtime_dir, False, 'passphrase',
                                handle_host_key=True, known_host_keys=['wrong_hostkey.pub'])
        assert 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED' in str(raises.value)

        # accept new host key
        if ferny.session.has_feature('KnownHostsCommand'):
            await self.run_test(key_dir, runtime_dir, True, 'passphrase',
                                handle_host_key=True, known_host_keys=['wrong_hostkey.pub'])
        else:
            # without KnownHostsCommand, we can't prompt
            with pytest.raises(ferny.SshChangedHostKeyError) as raises:
                await self.run_test(key_dir, runtime_dir, True, 'passphrase',
                                    handle_host_key=True, known_host_keys=['wrong_hostkey.pub'])
            assert 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED' in str(raises.value)

    #
    # without handling host keys
    #

    @pytest.mark.asyncio
    async def test_no_host_key_unknown(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        # note we only get a generic HostKeyError here, not Unknown*, as we don't enable KnownHostsCommand
        with pytest.raises(ferny.SshHostKeyError) as raises:
            await self.run_test(key_dir, runtime_dir, False, 'passphrase',
                                handle_host_key=False, known_host_keys=())
        assert str(raises.value) == 'Host key verification failed.'
        assert len(MockResponder.hostkey_args) == 1
        assert len(MockResponder.askpass_args) == 0

    @pytest.mark.asyncio
    async def test_no_host_key_known(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        await self.run_test(key_dir, runtime_dir, ZeroDivisionError(), 'passphrase',
                            handle_host_key=False)
        assert len(MockResponder.hostkey_args) == 0
        assert len(MockResponder.askpass_args) == 1

    @pytest.mark.asyncio
    async def test_no_host_key_changed(self, key_dir: pathlib.Path, runtime_dir: pathlib.Path) -> None:
        with pytest.raises(ferny.SshChangedHostKeyError) as raises:
            await self.run_test(key_dir, runtime_dir, ZeroDivisionError(), 'passphrase',
                                handle_host_key=False, known_host_keys=['wrong_hostkey.pub'])
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
