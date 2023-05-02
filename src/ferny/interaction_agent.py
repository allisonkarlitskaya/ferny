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

import ast
import asyncio
import logging
import socket
import os
import re

from typing import Dict, List, Optional, TextIO, Tuple

logger = logging.getLogger(__name__)


class InteractionError(Exception):
    pass


try:
    recv_fds = socket.recv_fds
    send_fds = socket.send_fds
except AttributeError:
    # Python < 3.9
    import array

    def recv_fds(sock, bufsize, maxfds, flags=0):
        fds = array.array("i")
        msg, ancdata, flags, addr = sock.recvmsg(bufsize, socket.CMSG_LEN(maxfds * fds.itemsize))
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if (cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS):
                fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
        return msg, list(fds), flags, addr

    def send_fds(sock, buffers, fds, flags=0, address=None):
        return sock.sendmsg(buffers, [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])


def get_running_loop() -> asyncio.AbstractEventLoop:
    try:
        return asyncio.get_running_loop()
    except AttributeError:
        # Python 3.6
        return asyncio.get_event_loop()


# https://discuss.python.org/t/expanding-asyncio-support-for-socket-apis/19277/8
async def wait_readable(fd: int) -> None:
    loop = get_running_loop()
    future = loop.create_future()
    loop.add_reader(fd, future.set_result, None)
    try:
        await future
    finally:
        loop.remove_reader(fd)


class InteractionResponder:
    async def do_askpass(self, messages: str, prompt: str, hint: str) -> Optional[str]:
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

    async def do_custom_command(self, command: str, args: Tuple, fds: List[int], stderr: str) -> None:
        """Handle a custom command.

        The command name, its arguments, the passed fds, and the stderr leading
        up to the command invocation are all provided.

        See doc/interaction-protocol.md
        """

    async def _askpass_task(self, args: List[str], env: Dict[str, str],
                            status: TextIO, stdout: TextIO, stderr: str) -> None:
        logger.debug('_askpass_task(%s, %d, %s, %s, %s)', args, len(env), status, stdout, stderr)

        if len(args) == 2:
            # normal askpass
            answer = await self.do_askpass(stderr, args[1], env.get('SSH_ASKPASS_PROMPT', ''))
            if answer is not None:
                print(answer, file=stdout)
                print(0, file=status)

        elif len(args) == 6:
            # KnownHostsCommand
            argv0, reason, host, algorithm, key, fingerprint = args
            if reason in ['ADDRESS', 'HOSTNAME']:
                if await self.do_hostkey(reason, host, algorithm, key, fingerprint):
                    print(host, algorithm, key, file=stdout)
            print(0, file=status)

        else:
            logger.error('Incorrect number of command-line arguments to ferny-askpass: %s', args)

    async def _askpass_command(self, args: Tuple, fds: List[int], stderr: str) -> None:
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
            # We want to run until either our askpass task is done or status_fd
            # reads ready. Once either of those cases becomes true, we cancel the
            # other task and collect results so that we propagate any exceptions
            # that were raised.
            loop = get_running_loop()
            tasks = [loop.create_task(self._askpass_task(argv, env, status, stdout, stderr)),
                     loop.create_task(wait_readable(status.fileno()))]
            (done,), (pending,) = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            logger.debug('do_askpass_command done waiting: done=%s pending=%s', done, pending)
            pending.cancel()
            await done

    # This is the only "public" method on the responder.  It only gets called by the agent.
    async def run_command(self, command: str, args: Tuple, fds: List[int], stderr: str) -> None:
        logger.debug('run_command(%s, %s, %s, %s)', command, args, fds, stderr)
        if command == 'ferny.askpass':
            await self._askpass_command(args, fds, stderr)
        else:
            await self.do_custom_command(command, args, fds, stderr)


class InteractionAgent:
    responder: InteractionResponder
    ours: socket.socket
    theirs: socket.socket
    buffer: bytes
    connected: bool

    def __init__(self, responder: InteractionResponder):
        self.buffer = b''
        self.ours, self.theirs = socket.socketpair()
        self.connected = False
        self.responder = responder

    def fileno(self) -> int:
        return self.theirs.fileno()

    async def invoke_command(self, stderr: bytes, command_blob: bytes, fds: List[int]) -> None:
        logger.debug('invoke_command(%s, %s, %s)', stderr, command_blob, fds)
        try:
            command, args = ast.literal_eval(command_blob.decode('utf-8'))
            if not isinstance(command, str) or not isinstance(args, tuple):
                raise TypeError('Invalid argument types')
        except (UnicodeDecodeError, SyntaxError, ValueError, TypeError) as exc:
            logger.error('Received invalid ferny command: %s: %s', command_blob, exc)
            return

        if command == 'ferny.end':
            logger.debug('  ferny.end -> setting connected=True')
            self.connected = True
            return

        await self.responder.run_command(command, args, fds, stderr.decode('utf-8'))

    COMMAND_RE = re.compile(b'\0ferny\0([^\n]*)\0\0\n')

    async def communicate(self) -> None:
        self.theirs.close()

        # Various bits of code call .pop() on the list to claim a particular
        # fd, but the ones that remain are our responsibility to close: we do
        # that at the end of each loop iteration, in the finally: block.
        fds: List[int] = []

        while not self.connected:
            try:
                # Wait for a message to come in, and read it
                await wait_readable(self.ours.fileno())
                data, fds, _flags, _addr = recv_fds(self.ours, 4096, 10)
                if not data:
                    raise InteractionError(self.buffer.decode('utf-8').strip())

                # Add to the buffer
                self.buffer += data

                # Read zero or more "remote" messages
                chunks = InteractionAgent.COMMAND_RE.split(self.buffer)
                while len(chunks) > 1:
                    await self.invoke_command(chunks[0], chunks[1], [])
                    chunks = chunks[2:]
                self.buffer = chunks[0]

                # Maybe read one "local" message
                if fds:
                    assert self.buffer.endswith(b'\0'), self.buffer
                    stderr = self.buffer[:-1]
                    self.buffer = b''
                    with open(fds.pop(0), 'rb') as command_channel:
                        command = command_channel.read()
                    await self.invoke_command(stderr, command, fds)

            finally:
                while fds:
                    os.close(fds.pop())

        logger.debug('agent.communicate() complete.')
