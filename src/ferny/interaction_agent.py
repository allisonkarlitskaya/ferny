# ferny - asyncio SSH client library, using ssh(1)
#
# Copyright (C) 2023 Allison Karlitskaya <allison.karlitskaya@redhat.com>
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

import array
import ast
import asyncio
import contextlib
import logging
import os
import re
import socket
import tempfile
from typing import Any, Callable, ClassVar, Generator, Sequence

from . import interaction_client

logger = logging.getLogger(__name__)


COMMAND_RE = re.compile(b'\0ferny\0([^\n]*)\0\0\n')
COMMAND_TEMPLATE = '\0ferny\0{(command, args)!r}\0\0\n'

BEIBOOT_GADGETS = {
    "command": fr"""
        import sys
        def command(command, *args):
            sys.stderr.write(f{COMMAND_TEMPLATE!r})
            sys.stderr.flush()
    """,
    "end": r"""
        def end():
            command('ferny.end')
    """,
}


class InteractionError(Exception):
    pass


try:
    recv_fds = socket.recv_fds
except AttributeError:
    # Python < 3.9

    def recv_fds(
        sock: socket.socket, bufsize: int, maxfds: int, flags: int = 0
    ) -> 'tuple[bytes, list[int], int, None]':
        fds = array.array("i")
        msg, ancdata, flags, addr = sock.recvmsg(bufsize, socket.CMSG_LEN(maxfds * fds.itemsize))
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if (cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS):
                fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
        return msg, list(fds), flags, addr


def get_running_loop() -> asyncio.AbstractEventLoop:
    try:
        return asyncio.get_running_loop()
    except AttributeError:
        # Python 3.6
        return asyncio.get_event_loop()


class InteractionHandler:
    commands: ClassVar[Sequence[str]]

    async def run_command(self, command: str, args: 'tuple[object, ...]', fds: 'list[int]', stderr: str) -> None:
        raise NotImplementedError


class AskpassHandler(InteractionHandler):
    commands: ClassVar[Sequence[str]] = ('ferny.askpass',)

    async def do_askpass(self, messages: str, prompt: str, hint: str) -> 'str | None':
        """Prompt the user for an authentication or confirmation interaction.

        'messages' is data that was sent to stderr before the interaction was requested.
        'prompt' is the interaction prompt.

        The expected response type depends on hint:

            - "confirm": ask for permission, returning "yes" if accepted
                - example: authorizing agent operation

            - "none": show a request without need for a response
                - example: please touch your authentication token

            - otherwise: return a password or other form of text token
                - examples: enter password, unlock private key

        In any case, the function should properly handle cancellation.  For the
        "none" case, this will be the normal way to dismiss the dialog.
        """
        return None

    async def do_hostkey(self, reason: str, host: str, algorithm: str, key: str, fingerprint: str) -> bool:
        """Prompt the user for a decision regarding acceptance of a host key.

        The "reason" will be either "HOSTNAME" or "ADDRESS" (if `CheckHostIP` is enabled).

        The host, algorithm, and key parameters are the values in the form that
        they would appear one a single line in the known hosts file.  The
        fingerprint is the key fingerprint in the format that ssh would
        normally present it to the user.

        In case the host key should be accepted, this function needs to return
        True.  Returning False means that ssh implements its default logic.  To
        interrupt the connection, raise an exception.
        """
        return False

    async def do_custom_command(
        self, command: str, args: 'tuple[object, ...]', fds: 'list[int]', stderr: str
    ) -> None:
        """Handle a custom command.

        The command name, its arguments, the passed fds, and the stderr leading
        up to the command invocation are all provided.

        See doc/interaction-protocol.md
        """

    async def _askpass_command(self, args: 'tuple[object, ...]', fds: 'list[int]', stderr: str) -> None:
        logger.debug('_askpass_command(%s, %s, %s)', args, fds, stderr)
        try:
            argv, env = args
            assert isinstance(argv, list)
            assert all(isinstance(arg, str) for arg in argv)
            assert isinstance(env, dict)
            assert all(isinstance(key, str) and isinstance(val, str) for key, val in env.items())
            assert len(fds) == 2
        except (ValueError, TypeError, AssertionError) as exc:
            logger.error('Invalid arguments to askpass interaction: %s, %s: %s', args, fds, exc)
            return

        with open(fds.pop(0), 'w') as status, open(fds.pop(0), 'w') as stdout:
            try:
                loop = get_running_loop()
                try:
                    task = asyncio.current_task()
                except AttributeError:
                    task = asyncio.Task.current_task()  # type:ignore[attr-defined] # (Python 3.6)
                assert task is not None
                loop.add_reader(status, task.cancel)

                if len(argv) == 2:
                    # normal askpass
                    prompt = argv[1]
                    hint = env.get('SSH_ASKPASS_PROMPT', '')
                    logger.debug('do_askpass(%r, %r, %r)', stderr, prompt, hint)
                    answer = await self.do_askpass(stderr, prompt, hint)
                    logger.debug('do_askpass answer %r', answer)
                    if answer is not None:
                        print(answer, file=stdout)
                        print(0, file=status)

                elif len(argv) == 6:
                    # KnownHostsCommand
                    argv0, reason, host, algorithm, key, fingerprint = argv
                    if reason in ['ADDRESS', 'HOSTNAME']:
                        logger.debug('do_hostkey(%r, %r, %r, %r, %r)', reason, host, algorithm, key, fingerprint)
                        if await self.do_hostkey(reason, host, algorithm, key, fingerprint):
                            print(host, algorithm, key, file=stdout)
                    else:
                        logger.debug('ignoring KnownHostsCommand reason %r', reason)

                    print(0, file=status)

                else:
                    logger.error('Incorrect number of command-line arguments to ferny-askpass: %s', argv)
            finally:
                loop.remove_reader(status)

    async def run_command(self, command: str, args: 'tuple[object, ...]', fds: 'list[int]', stderr: str) -> None:
        logger.debug('run_command(%s, %s, %s, %s)', command, args, fds, stderr)
        if command == 'ferny.askpass':
            await self._askpass_command(args, fds, stderr)
        else:
            await self.do_custom_command(command, args, fds, stderr)


class InteractionAgent:
    _handlers: 'dict[str, InteractionHandler]'

    _loop: asyncio.AbstractEventLoop

    _tasks: 'set[asyncio.Task]'

    _buffer: bytearray
    _ours: socket.socket
    _theirs: socket.socket

    _completion_future: 'asyncio.Future[str]'
    _pending_result: 'None | str | Exception' = None
    _end: bool = False

    def _consider_completion(self) -> None:
        logger.debug('_consider_completion(%r)', self)

        if self._pending_result is None or self._tasks:
            logger.debug('  but not ready yet')

        elif self._completion_future.done():
            logger.debug('  but already complete')

        elif isinstance(self._pending_result, str):
            logger.debug('  submitting stderr (%r) to completion_future', self._pending_result)
            self._completion_future.set_result(self._pending_result)

        else:
            logger.debug('  submitting exception (%r) to completion_future')
            self._completion_future.set_exception(self._pending_result)

    def _result(self, result: 'str | Exception') -> None:
        logger.debug('_result(%r, %r)', self, result)

        if self._pending_result is None:
            self._pending_result = result

        if self._ours.fileno() != -1:
            logger.debug('  remove_reader(%r)', self._ours)
            self._loop.remove_reader(self._ours.fileno())

        for task in self._tasks:
            logger.debug('    cancel(%r)', task)
            task.cancel()

        logger.debug('  closing sockets')
        self._theirs.close()  # idempotent
        self._ours.close()

        self._consider_completion()

    def _invoke_command(self, stderr: bytes, command_blob: bytes, fds: 'list[int]') -> None:
        logger.debug('_invoke_command(%r, %r, %r)', stderr, command_blob, fds)
        try:
            command, args = ast.literal_eval(command_blob.decode())
            if not isinstance(command, str) or not isinstance(args, tuple):
                raise TypeError('Invalid argument types')
        except (UnicodeDecodeError, SyntaxError, ValueError, TypeError) as exc:
            logger.error('Received invalid ferny command: %s: %s', command_blob, exc)
            return

        if command == 'ferny.end':
            self._end = True
            self._result(self._buffer.decode(errors='replace'))
            return

        try:
            handler = self._handlers[command]
        except KeyError:
            logger.error('Received unhandled ferny command: %s', command)
            return

        # The task is responsible for the list of fds and removing itself
        # from the set.
        task_fds = list(fds)
        task = self._loop.create_task(handler.run_command(command, args, task_fds, stderr.decode()))

        def bottom_half(completed_task: asyncio.Task) -> None:
            assert completed_task is task
            while task_fds:
                os.close(task_fds.pop())
            self._tasks.remove(task)

            try:
                task.result()
                logger.debug('%r completed cleanly', handler)
            except asyncio.CancelledError:
                # this is not an error — it just means ferny-askpass exited via signal
                logger.debug('%r was cancelled', handler)
            except Exception as exc:
                logger.debug('%r raised %r', handler, exc)
                self._result(exc)

            self._consider_completion()

        task.add_done_callback(bottom_half)
        self._tasks.add(task)
        fds[:] = []

    def _got_data(self, data: bytes, fds: 'list[int]') -> None:
        logger.debug('_got_data(%r, %r)', data, fds)

        if data == b'':
            self._result(self._buffer.decode(errors='replace'))
            return

        self._buffer.extend(data)

        # Read zero or more "remote" messages
        chunks = COMMAND_RE.split(self._buffer)
        self._buffer = bytearray(chunks.pop())
        while len(chunks) > 1:
            self._invoke_command(chunks[0], chunks[1], [])
            chunks = chunks[2:]

        # Maybe read one "local" message
        if fds:
            assert self._buffer.endswith(b'\0'), self._buffer
            stderr = self._buffer[:-1]
            self._buffer = bytearray(b'')
            with open(fds.pop(0), 'rb') as command_channel:
                command = command_channel.read()
            self._invoke_command(stderr, command, fds)

    def _read_ready(self) -> None:
        try:
            data, fds, _flags, _addr = recv_fds(self._ours, 4096, 10, flags=socket.MSG_DONTWAIT)
        except BlockingIOError:
            return
        except OSError as exc:
            self._result(exc)
        else:
            self._got_data(data, fds)
        finally:
            while fds:
                os.close(fds.pop())

    def __init__(
        self,
        handlers: Sequence[InteractionHandler],
        loop: 'asyncio.AbstractEventLoop | None' = None,
        done_callback: 'Callable[[asyncio.Future[str]], None] | None' = None,
    ) -> None:
        self._loop = loop or get_running_loop()
        self._completion_future = self._loop.create_future()
        self._tasks = set()
        self._handlers = {}

        for handler in handlers:
            for command in handler.commands:
                self._handlers[command] = handler

        if done_callback is not None:
            self._completion_future.add_done_callback(done_callback)

        self._theirs, self._ours = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self._buffer = bytearray()

    def fileno(self) -> int:
        return self._theirs.fileno()

    def start(self) -> None:
        logger.debug('start(%r)', self)
        if self._ours.fileno() != -1:
            logger.debug('  add_reader(%r)', self._ours)
            self._loop.add_reader(self._ours.fileno(), self._read_ready)
        else:
            logger.debug('  ...but agent is already finished.')

        logger.debug('  close(%r)', self._theirs)
        self._theirs.close()

    def force_completion(self) -> None:
        logger.debug('force_completion(%r)', self)

        # read any residual data on stderr, but don't process commands, and
        # don't block
        try:
            if self._ours.fileno() != -1:
                logger.debug('  draining pending stderr data (non-blocking)')
                with contextlib.suppress(BlockingIOError):
                    while True:
                        data = self._ours.recv(4096, socket.MSG_DONTWAIT)
                        logger.debug('    got %d bytes', len(data))
                        if not data:
                            break
                        self._buffer.extend(data)
        except OSError as exc:
            self._result(exc)
        else:
            self._result(self._buffer.decode(errors='replace'))

    async def communicate(self) -> None:
        logger.debug('_communicate(%r)', self)
        try:
            self.start()
            # We assume that we are the only ones to write to
            # self._completion_future.  If we directly await it, though, it can
            # also have a asyncio.CancelledError posted to it from outside.
            # Shield it to prevent that from happening.
            stderr = await asyncio.shield(self._completion_future)
            logger.debug('_communicate(%r) stderr result is %r', self, stderr)
        finally:
            logger.debug('_communicate finished.  Ensuring completion.')
            self.force_completion()
        if not self._end:
            logger.debug('_communicate never saw ferny.end.  raising InteractionError.')
            raise InteractionError(stderr.strip())


def write_askpass_to_tmpdir(tmpdir: str) -> str:
    askpass_path = os.path.join(tmpdir, 'ferny-askpass')
    fd = os.open(askpass_path, os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC | os.O_EXCL | os.O_NOFOLLOW, 0o777)
    try:
        os.write(fd, __loader__.get_data(interaction_client.__file__))  # type: ignore
    finally:
        os.close(fd)
    return askpass_path


@contextlib.contextmanager
def temporary_askpass(**kwargs: Any) -> Generator[str, None, None]:
    with tempfile.TemporaryDirectory(**kwargs) as directory:
        yield write_askpass_to_tmpdir(directory)
