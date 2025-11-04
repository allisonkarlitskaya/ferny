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

import asyncio
import contextlib
import logging
import typing
from typing import Any, Callable, Iterable, Sequence, TypeVar

from .interaction_agent import InteractionAgent, InteractionHandler, get_running_loop
from .ssh_errors import get_exception_for_ssh_stderr

logger = logging.getLogger(__name__)

P = TypeVar('P', bound=asyncio.Protocol)


class SubprocessError(Exception):
    returncode: int
    stderr: str

    def __init__(self, returncode: int, stderr: str) -> None:
        super().__init__(returncode, stderr)
        self.returncode = returncode
        self.stderr = stderr


class FernyTransport(asyncio.Transport, asyncio.SubprocessProtocol):
    _agent: InteractionAgent
    _exec_task: 'asyncio.Task[tuple[asyncio.SubprocessTransport, FernyTransport]]'
    _is_ssh: bool
    _protocol: asyncio.Protocol
    _protocol_disconnected: bool = False

    # These get initialized in connection_made() and once set, never get unset.
    _subprocess_transport: 'asyncio.SubprocessTransport | None' = None
    _stdin_transport: 'asyncio.WriteTransport | None' = None
    _stdout_transport: 'asyncio.ReadTransport | None' = None

    # We record events that might build towards a connection termination here
    # and consider them from _consider_disconnect() in order to try to get the
    # best possible Exception for the protocol, rather than just taking the
    # first one (which is likely to be somewhat random).
    _exception: 'Exception | None' = None
    _stderr_output: 'str | None' = None
    _returncode: 'int | None' = None
    _transport_disconnected: bool = False
    _closed: bool = False

    @classmethod
    def spawn(
        cls: 'type[typing.Self]',
        protocol_factory: Callable[[], P],
        args: Sequence[str],
        loop: 'asyncio.AbstractEventLoop | None' = None,
        interaction_handlers: Sequence[InteractionHandler] = (),
        is_ssh: bool = True,
        **kwargs: Any
    ) -> 'tuple[typing.Self, P]':
        """Connects a FernyTransport to a protocol, using the given command.

        This spawns an external command and connects the stdin and stdout of
        the command to the protocol returned by the factory.

        An instance of ferny.InteractionAgent is created and attached to the
        stderr of the spawned process, using the provided handlers.  It is the
        responsibility of the caller to ensure that:
          - a `ferny-askpass` client program is installed somewhere; and
          - any relevant command-line arguments or environment variables are
            passed correctly to the program to be spawned

        This function returns immediately and never raises exceptions, assuming
        all preconditions are met.

        If spawning the process fails then connection_lost() will be
        called with the relevant OSError, even before connection_made() is
        called.  This is somewhat non-standard behaviour, but is the easiest
        way to report these errors without making this function async.

        Once the process is successfully executed, connection_made() will be
        called and the transport can be used as normal.  connection_lost() will
        be called if the process exits or another error occurs.

        The return value of this function is the transport, but it exists in a
        semi-initialized state.  You can call .close() on it, but nothing else.
        Once .connection_made() is called, you can call all the other
        functions.

        After you call this function, `.connection_lost()` will be called on
        your Protocol, exactly once, no matter what.  Until that happens, you
        are responsible for holding a reference to the returned transport.

        :param args: the full argv of the command to spawn
        :param loop: the event loop to use.  If none is provided, we use the
            one which is (read: must be) currently running.
        :param interaction_handlers: the handlers passed to the
            InteractionAgent
        :param is_ssh: whether we should attempt to interpret stderr as ssh
            error messages
        :param kwargs: anything else is passed through to `subprocess_exec()`
        :returns: the usual `(Transport, Protocol)` pair
        """
        logger.debug('spawn(%r, %r, %r)', cls, protocol_factory, args)

        protocol = protocol_factory()
        self = cls(protocol)
        self._is_ssh = is_ssh

        if loop is None:
            loop = get_running_loop()

        self._agent = InteractionAgent(interaction_handlers, loop, self._interaction_completed)
        kwargs.setdefault('stderr', self._agent.fileno())

        # As of Python 3.12 this isn't really asynchronous (since it uses the
        # subprocess module, which blocks while waiting for the exec() to
        # complete in the child), but we have to deal with the complication of
        # the async interface anyway.  Since we, ourselves, want to export a
        # non-async interface, that means that we need a task here and a
        # bottom-half handler below.
        self._exec_task = loop.create_task(loop.subprocess_exec(lambda: self, *args, **kwargs))

        def exec_completed(task: "asyncio.Task[tuple[asyncio.SubprocessTransport, typing.Self]]") -> None:
            logger.debug('exec_completed(%r, %r)', self, task)
            assert task is self._exec_task
            try:
                transport, me = task.result()
                assert me is self
                logger.debug('  success.')
            except asyncio.CancelledError:
                return  # in that case, do nothing
            except OSError as exc:
                logger.debug('  OSError %r', exc)
                self.close(exc)
                return

            # Our own .connection_made() handler should have gotten called by
            # now.  Make sure everything got filled in properly.
            assert self._subprocess_transport is transport
            assert self._stdin_transport is not None
            assert self._stdout_transport is not None

            # Ask the InteractionAgent to start processing stderr.
            self._agent.start()

        self._exec_task.add_done_callback(exec_completed)

        return self, protocol

    def __init__(self, protocol: asyncio.Protocol) -> None:
        self._protocol = protocol

    def _consider_disconnect(self) -> None:
        logger.debug('_consider_disconnect(%r)', self)
        # We cannot disconnect as long as any of these three things are happening
        if not self._exec_task.done():
            logger.debug('  exec_task still running %r', self._exec_task)
            return

        if self._subprocess_transport is not None and not self._transport_disconnected:
            logger.debug('  transport still connected %r', self._subprocess_transport)
            return

        if self._stderr_output is None:
            logger.debug('  agent still running')
            return

        # All conditions for disconnection are satisfied.
        if self._protocol_disconnected:
            logger.debug('  already disconnected')
            return
        self._protocol_disconnected = True

        # Now we just need to determine what we report to the protocol...
        if self._exception is not None:
            # If we got an exception reported, that's our reason for closing.
            logger.debug('  disconnect with exception %r', self._exception)
            self._protocol.connection_lost(self._exception)
        elif self._returncode == 0 or self._closed:
            # If we called close() or have a zero return status, that's a clean
            # exit, regardless of noise that might have landed in stderr.
            logger.debug('  clean disconnect')
            self._protocol.connection_lost(None)
        elif self._is_ssh and self._returncode == 255:
            # This is an error code due to an SSH failure.  Try to interpret it.
            logger.debug('  disconnect with ssh error %r', self._stderr_output)
            self._protocol.connection_lost(get_exception_for_ssh_stderr(self._stderr_output))
        else:
            # Otherwise, report the stderr text and return code.
            logger.debug('  disconnect with exit code %r, stderr %r', self._returncode, self._stderr_output)
            # We surely have _returncode set here, since otherwise:
            #  - exec_task failed with an exception (which we handle above); or
            #  - we're still connected...
            assert self._returncode is not None
            self._protocol.connection_lost(SubprocessError(self._returncode, self._stderr_output))

    def _interaction_completed(self, future: 'asyncio.Future[str]') -> None:
        logger.debug('_interaction_completed(%r, %r)', self, future)
        try:
            self._stderr_output = future.result()
            logger.debug('  stderr: %r', self._stderr_output)
        except Exception as exc:
            logger.debug('  exception: %r', exc)
            self._stderr_output = ''  # we need to set this in order to complete
            self.close(exc)

        self._consider_disconnect()

    # BaseProtocol implementation
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        logger.debug('connection_made(%r, %r)', self, transport)
        assert isinstance(transport, asyncio.SubprocessTransport)
        self._subprocess_transport = transport

        stdin_transport = transport.get_pipe_transport(0)
        assert isinstance(stdin_transport, asyncio.WriteTransport)
        self._stdin_transport = stdin_transport

        stdout_transport = transport.get_pipe_transport(1)
        assert isinstance(stdout_transport, asyncio.ReadTransport)
        self._stdout_transport = stdout_transport

        stderr_transport = transport.get_pipe_transport(2)
        assert stderr_transport is None

        logger.debug('calling connection_made(%r, %r)', self, self._protocol)
        self._protocol.connection_made(self)

    def connection_lost(self, exc: 'Exception | None') -> None:
        logger.debug('connection_lost(%r, %r)', self, exc)
        if self._exception is None:
            self._exception = exc
        self._transport_disconnected = True
        self._consider_disconnect()

    # SubprocessProtocol implementation
    def pipe_data_received(self, fd: int, data: bytes) -> None:
        logger.debug('pipe_data_received(%r, %r, %r)', self, fd, len(data))
        assert fd == 1  # stderr is handled separately
        self._protocol.data_received(data)

    def pipe_connection_lost(self, fd: int, exc: 'Exception | None') -> None:
        logger.debug('pipe_connection_lost(%r, %r, %r)', self, fd, exc)
        assert fd in (0, 1)  # stderr is handled separately

        # We treat this as a clean close
        if isinstance(exc, BrokenPipeError):
            exc = None

        # Record serious errors to propagate them to the protocol
        # If this is a clean exit on stdout, report an EOF
        if exc is not None:
            self.close(exc)
        elif fd == 1 and not self._closed:
            if not self._protocol.eof_received():
                self.close()

    def process_exited(self) -> None:
        logger.debug('process_exited(%r)', self)
        assert self._subprocess_transport is not None
        self._returncode = self._subprocess_transport.get_returncode()
        logger.debug('  ._returncode = %r', self._returncode)
        self._agent.force_completion()

    def pause_writing(self) -> None:
        logger.debug('pause_writing(%r)', self)
        self._protocol.pause_writing()

    def resume_writing(self) -> None:
        logger.debug('resume_writing(%r)', self)
        self._protocol.resume_writing()

    # Transport implementation.  Most of this is straight delegation.
    def close(self, exc: 'Exception | None' = None) -> None:
        logger.debug('close(%r, %r)', self, exc)
        self._closed = True
        if self._exception is None:
            logger.debug('  setting exception %r', exc)
            self._exception = exc
        if not self._exec_task.done():
            logger.debug('  cancelling _exec_task')
            self._exec_task.cancel()
        if self._subprocess_transport is not None:
            logger.debug('  closing _subprocess_transport')
            # https://github.com/python/cpython/issues/112800
            with contextlib.suppress(PermissionError):
                self._subprocess_transport.close()
        self._agent.force_completion()

    def is_closing(self) -> bool:
        assert self._subprocess_transport is not None
        return self._subprocess_transport.is_closing()

    def get_extra_info(self, name: str, default: object = None) -> object:
        assert self._subprocess_transport is not None
        return self._subprocess_transport.get_extra_info(name, default)

    def set_protocol(self, protocol: asyncio.BaseProtocol) -> None:
        assert isinstance(protocol, asyncio.Protocol)
        self._protocol = protocol

    def get_protocol(self) -> asyncio.Protocol:
        return self._protocol

    def is_reading(self) -> bool:
        assert self._stdout_transport is not None
        try:
            return self._stdout_transport.is_reading()
        except NotImplementedError:
            # This is (incorrectly) unimplemented before Python 3.11
            return not self._stdout_transport._paused  # type:ignore[attr-defined]
        except AttributeError:
            # ...and in Python 3.6 it's even worse
            try:
                selector = self._stdout_transport._loop._selector  # type:ignore[attr-defined]
                selector.get_key(self._stdout_transport._fileno)  # type:ignore[attr-defined]
                return True
            except KeyError:
                return False

    def pause_reading(self) -> None:
        assert self._stdout_transport is not None
        self._stdout_transport.pause_reading()

    def resume_reading(self) -> None:
        assert self._stdout_transport is not None
        self._stdout_transport.resume_reading()

    def abort(self) -> None:
        assert self._stdin_transport is not None
        assert self._subprocess_transport is not None
        self._stdin_transport.abort()
        self._subprocess_transport.kill()

    def can_write_eof(self) -> bool:
        assert self._stdin_transport is not None
        return self._stdin_transport.can_write_eof()  # will always be True

    def get_write_buffer_size(self) -> int:
        assert self._stdin_transport is not None
        return self._stdin_transport.get_write_buffer_size()

    def get_write_buffer_limits(self) -> 'tuple[int, int]':
        assert self._stdin_transport is not None
        return self._stdin_transport.get_write_buffer_limits()

    def set_write_buffer_limits(self, high: 'int | None' = None, low: 'int | None' = None) -> None:
        assert self._stdin_transport is not None
        return self._stdin_transport.set_write_buffer_limits(high, low)

    def write(self, data: 'bytes | bytearray | memoryview') -> None:
        assert self._stdin_transport is not None
        return self._stdin_transport.write(data)

    def writelines(self, list_of_data: 'Iterable[bytes | bytearray | memoryview]') -> None:
        assert self._stdin_transport is not None
        return self._stdin_transport.writelines(list_of_data)

    def write_eof(self) -> None:
        assert self._stdin_transport is not None
        return self._stdin_transport.write_eof()

    # We don't really implement SubprocessTransport, but provide these as
    # "extras" to our user.
    def get_pid(self) -> int:
        assert self._subprocess_transport is not None
        return self._subprocess_transport.get_pid()

    def get_returncode(self) -> 'int | None':
        return self._returncode

    def kill(self) -> None:
        assert self._subprocess_transport is not None
        self._subprocess_transport.kill()

    def send_signal(self, number: int) -> None:
        assert self._subprocess_transport is not None
        self._subprocess_transport.send_signal(number)

    def terminate(self) -> None:
        assert self._subprocess_transport is not None
        self._subprocess_transport.terminate()
