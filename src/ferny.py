# ferny - asyncio SSH client library, using ssh(1)
#
# Copyright (C) 2022 Allison Karlitskaya <allison.karlitskaya@redhat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import ast
import asyncio
import ctypes
import logging
import os
import shlex
import signal
import tempfile
import textwrap

from typing import Callable, Mapping, Sequence, Optional

prctl = ctypes.cdll.LoadLibrary('libc.so.6').prctl
logger = logging.getLogger(__name__)
RUN = os.environ.get('XDG_RUNTIME_DIR', '/run')
FERNY_DIR = os.path.join(RUN, 'ferny')
PR_SET_PDEATHSIG = 1


class CreateWatcher:
    path: str

    def __init__(self, path: str):
        self.path = path

    async def wait(self):
        raise NotImplementedError

    async def watch(self):
        logger.debug('%s: waiting for %s', self, self.path)
        while not os.path.exists(self.path):
            await self.wait()
        logger.debug('%s: %s exists.  returning.', self, self.path)


class PollingCreateWatcher(CreateWatcher):
    async def wait(self):
        logger.debug('%s: sleeping', self)
        await asyncio.sleep(0.1)


# TODO: CreateWatcher implementation backed by systemd_ctypes inotify


class SubprocessContext:
    def wrap_subprocess_args(self, args: Sequence[str]) -> Sequence[str]:
        """Return the args required to launch a process in the given context.

        For example, this might return a vector with
            ["sudo"]
        or
            ["flatpak-spawn", "--host"]
        prepended.

        It is also possible that more substantial changes may be performed.

        This function is not permitted to modify its argument, although it may
        (optionally) return it unmodified, if no changes are required.
        """
        return args

    def wrap_subprocess_env(self, env: Mapping[str, str]) -> Mapping[str, str]:
        """Return the envp required to launch a process in the given context.

        For example, this might set the "SUDO_ASKPASS" environment variable, if
        needed.

        As with wrap_subprocess_args(), this function is not permitted to
        modify its argument, although it may (optionally) return it unmodified
        if no changes are required.
        """
        return env


class Askpass(asyncio.StreamReaderProtocol):
    async def askpass(self, message: str, hint: str) -> Optional[str]:
        """Prompt the user for an authentication or confirmation interaction.

        The message should always be displayed.

        The expected response type depends on hint:

            - "confirm": ask for permission, returning "yes" if accepted
                - example: authorizing agent operation
            - "notify": show a request without need for a response
                - example: please touch your authentication token
            - otherwise: return a password or other form of text token
                - examples: enter password, unlock private key

        In any case, the function should properly handle cancellation.  For the
        "notify" case, this will be the normal way to dismiss the dialog.
        """
        raise NotImplementedError

    async def _connection_cb(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        logger.debug('got askpass connection')
        message, hint = ast.literal_eval((await reader.readline()).decode('utf-8'))

        answer = await self.askpass(message, hint)

        if answer:
            result = f'{answer}\n', 0
        else:
            result = '', 1

        writer.write(f'{result!r}'.encode('utf-8'))
        await writer.drain()
        writer.close()
        logger.debug('sent askpass result %s', result)

    # A small hack: the default StreamReaderProtocol doesn't cancel the task
    # when the remote sends EOF, but for our case, that means that the askpass
    # client got killed and we want to cancel the request.
    _task: Optional[asyncio.Task]

    def __init__(self):
        super().__init__(asyncio.StreamReader(), self._connection_cb)

    def eof_received(self) -> bool:
        super().eof_received()
        if self._task is not None and not self._task.done():
            logger.debug('cancelling %s task', self)
            self._task.cancel()
        return False


class Session(SubprocessContext):
    # Set after .connect() called, even if failed
    _controldir: Optional[tempfile.TemporaryDirectory]
    _controlsock: Optional[str]
    _process: Optional[asyncio.subprocess.Process]

    # Set if connected, else None
    _communicate_task: Optional[asyncio.Task]

    async def await_exit(self) -> None:
        assert self._process is not None
        stdout, stderr = await self._process.communicate()

        if self._process.returncode:
            raise RuntimeError(stderr)

    async def await_socket(self) -> None:
        assert self._controlsock is not None
        watcher = PollingCreateWatcher(self._controlsock)
        await watcher.watch()

    async def connect(self,
                      destination: str,
                      configfile: Optional[str] = None,
                      identity_file: Optional[str] = None,
                      login_name: Optional[str] = None,
                      options: Optional[Mapping[str, str]] = None,
                      pkcs11: Optional[str] = None,
                      port: Optional[int] = None,
                      askpass_factory: Optional[Callable[[], Askpass]] = None) -> None:
        os.makedirs(FERNY_DIR, exist_ok=True)
        self._controldir = tempfile.TemporaryDirectory(dir=FERNY_DIR)
        self._controlsock = f'{self._controldir.name}/socket'

        env = dict(os.environ)

        if askpass_factory:
            askpass_path = f'{self._controldir.name}/askpass'
            askpass_sock_path = f'{self._controldir.name}/auth'

            with open(os.open(askpass_path, os.O_WRONLY | os.O_CREAT, 0o700), 'w') as file:
                file.write(textwrap.dedent(rf"""
                    #!/usr/bin/python3

                    import os
                    import ast
                    import socket
                    import sys

                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.connect({askpass_sock_path!r})
                    args = sys.argv[1], os.environ.get('SSH_ASKPASS_PROMPT', '')
                    sock.send(f'{{args!r}}\n'.encode('utf-8'))
                    answer, status = ast.literal_eval(sock.recv(100000).decode('utf-8'))
                    sys.stdout.write(answer)
                    sys.exit(status)
                """).lstrip())

            # See comments above for why we can't use vanilla
            # StreamReaderProtocol via asyncio.start_unix_server().
            loop = asyncio.get_running_loop()
            askpass_server = await loop.create_unix_server(askpass_factory, askpass_sock_path)
            env['SSH_ASKPASS'] = askpass_path
        else:
            askpass_server = None

        args = [
            '-M',
            '-N',
            '-S', self._controlsock,
        ]

        if configfile is not None:
            args.append(f'-F{configfile}')

        if identity_file is not None:
            args.append(f'-i{identity_file}')

        if options is not None:
            for key in options:  # Note: Mapping may not have .items()
                args.append(f'-o{key} {options[key]}')

        if pkcs11 is not None:
            args.append(f'-I{pkcs11}')

        if port is not None:
            args.append(f'-p{port}')

        if login_name is not None:
            args.append(f'-l{login_name}')

        # SSH_ASKPASS_REQUIRE is not generally available, so use setsid
        self._process = await asyncio.create_subprocess_exec(
            *('/usr/bin/ssh', *args, destination), env=env,
            start_new_session=True, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            preexec_fn=lambda: prctl(PR_SET_PDEATHSIG, signal.SIGKILL))

        communicate_task = asyncio.create_task(self.await_exit())
        connection_task = asyncio.create_task(self.await_socket())

        done, pending = await asyncio.wait((communicate_task, connection_task),
                                           return_when=asyncio.FIRST_COMPLETED)

        if askpass_server is not None:
            askpass_server.close()

        if communicate_task.done():
            connection_task.cancel()
            communicate_task.result()  # will throw
        else:
            assert connection_task.done()
            connection_task.result()  # None
            self._communicate_task = communicate_task

    def is_connected(self) -> bool:
        return self._communicate_task is not None

    async def wait(self) -> None:
        if self._communicate_task is not None:
            await self._communicate_task
            self._communicate_task.result()

    def exit(self) -> None:
        assert self._process is not None
        self._process.terminate()

    async def disconnect(self) -> None:
        self.exit()
        await self.wait()

    # Launching of processes
    def wrap_subprocess_args(self, args: Sequence[str]) -> Sequence[str]:
        assert self._controlsock is not None
        # 1. We specify the hostname as the empty string: it will be ignored
        #    when ssh is trying to use the control socket, but in case the
        #    socket has stopped working, ssh will try to fall back to directly
        #    connecting, in which case an empty hostname will prevent that.
        # 2. We need to quote the arguments — ssh will paste them together
        #    using only spaces, executing the result using the user's shell.
        return ('ssh', '-S', self._controlsock, '', *map(shlex.quote, args))
