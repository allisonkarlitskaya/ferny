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

from typing import Coroutine, Callable, Dict, List, Optional, TextIO

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


# https://discuss.python.org/t/expanding-asyncio-support-for-socket-apis/19277/8
async def wait_readable(loop: asyncio.AbstractEventLoop, fd: int) -> None:
    future = loop.create_future()
    loop.add_reader(fd, future.set_result, None)
    try:
        await future
    finally:
        loop.remove_reader(fd)


class Interaction:
    cmd: str
    args: List[str]
    env: Dict[str, str]
    stderr: str
    status: socket.socket
    stdout: TextIO

    def __init__(self, buffer: str, status: socket.socket, stdout: TextIO):
        self.stderr, sep, details = buffer.rpartition('\0ferny\0')
        assert sep, buffer
        args, env = ast.literal_eval(details)

        assert isinstance(args, list), args
        assert isinstance(env, dict), dict
        assert all(isinstance(item, str) for item in args), args
        assert all(isinstance(key, str) for key in env.keys()), env
        assert all(isinstance(val, str) for val in env.values()), env

        self.cmd = args[0]
        self.args, self.env = args[1:], env
        self.status = status
        self.stdout = stdout
        logger.debug('  args=%s stderr=%s', self.args, self.stderr)

    def writeline(self, line: str) -> None:
        try:
            # This is theoretically blocking, but it never will
            self.stdout.write(line + '\n')
            self.stdout.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # happens if the client was killed

    def done(self, returncode: int = 0) -> None:
        try:
            # This is theoretically blocking, but it never will
            self.status.send(str(returncode).encode('ascii'))
        except (BrokenPipeError, ConnectionResetError):
            pass  # happens if the client was killed

    def _task_done(self, task):
        # We must do this from outside of the task so that it always runs when
        # the task is done, even if an exception occurred.  If we fail to do
        # this, then the wait_readable() will never return and we'll deadlock.
        self.status.shutdown(socket.SHUT_WR)

    @staticmethod
    async def run(loop: asyncio.AbstractEventLoop,
                  buffer: str,
                  fds: List[int],
                  func: Callable[['Interaction'], Coroutine]) -> None:
        with socket.fromfd(fds[0], socket.AF_UNIX, socket.SOCK_STREAM) as status:
            with open(fds[1], 'w', closefd=False) as stdout:
                interaction = Interaction(buffer, status, stdout)
                # This is tricky.
                #
                # We need to watch the status fd for readability to find out
                # when the client program has exited.  That will happen either
                # in response to our task being done (and the shutdown() call
                # in _task_done) or in response to being killed from ssh.  That
                # happens for some types of prompts like "please touch your
                # hardware token".
                #
                # In case we got killed from ssh, and our own task is still
                # running, we need to cancel it.  In any case, we need to
                # collect the result of our task to make sure we propagate
                # exceptions: it's part of our API that exceptions raised in
                # the interaction responder can be caught by the caller to
                # .connect().
                #
                # Note: we use a finally: block in case an exception (like
                # KeyboardInterrupt) gets raised while awaiting readability.
                # In that case, we are still responsible for collecting the
                # result of the task.
                task = loop.create_task(func(interaction))
                task.add_done_callback(interaction._task_done)
                try:
                    await wait_readable(loop, status.fileno())
                finally:
                    if not task.done():
                        task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass


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


class InteractionAgent:
    responder: InteractionResponder
    ours: socket.socket
    theirs: socket.socket
    buffer: bytearray
    connected: bool

    def __init__(self, responder: InteractionResponder):
        self.buffer = bytearray()
        self.ours, self.theirs = socket.socketpair()
        self.connected = False
        self.responder = responder

    def fileno(self) -> int:
        return self.theirs.fileno()

    async def do_interaction(self, interaction: Interaction) -> None:
        logger.debug('running interaction %s %s', interaction.cmd, interaction.args)

        if len(interaction.args) == 0:
            # LocalCommand or send-stderr
            if interaction.cmd == 'send-stderr':
                send_fds(interaction.status, [b'\0'], [2])
            self.connected = True
            interaction.done()

        elif len(interaction.args) == 1:
            # normal askpass
            answer = await self.responder.do_askpass(interaction.stderr,
                                                     interaction.args[0],
                                                     interaction.env.get('SSH_ASKPASS_PROMPT', ''))
            if answer is not None:
                interaction.writeline(answer)
                interaction.done()
            else:
                interaction.done(1)

        elif len(interaction.args) == 5:
            # KnownHostsCommand
            reason, host, algorithm, key, fingerprint = interaction.args
            if reason in ['ADDRESS', 'HOSTNAME']:
                if await self.responder.do_hostkey(reason, host, algorithm, key, fingerprint):
                    interaction.writeline(f'{host} {algorithm} {key}\n')
            interaction.done()

        else:
            assert False, interaction.args

        logger.debug('returned result to client')

    async def communicate(self) -> None:
        self.theirs.close()

        try:
            loop = asyncio.get_running_loop()
        except AttributeError:
            # Python 3.6
            loop = asyncio.get_event_loop()
        fds: List[int] = []

        while not self.connected:
            await wait_readable(loop, self.ours.fileno())
            try:
                # We handle fds very carefully to avoid leaking them, even in case of exceptions
                data, fds, _flags, _addr = recv_fds(self.ours, 4096, 10)
                if not data:
                    raise InteractionError(self.buffer.decode('utf-8').strip())
                self.buffer += data
                if fds:
                    logger.debug('New interaction request incoming:')
                    await Interaction.run(loop, self.buffer.decode('utf-8'), fds, self.do_interaction)
                    logger.debug('Interaction is complete')
                    self.buffer.clear()
            finally:
                while fds:
                    os.close(fds.pop())
