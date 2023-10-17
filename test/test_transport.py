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
import errno
import os
import select
import signal
import subprocess
import sys
from pathlib import Path

import pytest

import ferny


# A version of ferny.SubprocessError that supports compare-by-value
# Useful for checking for expected exceptions in callbacks
class SubprocessError(ferny.SubprocessError):
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ferny.SubprocessError):
            return False
        return self.returncode == other.returncode and self.stderr == other.stderr


class MockProtocol(asyncio.Protocol):
    queue: 'asyncio.Queue[tuple[str, tuple[object, ...]]]'
    eof_result: bool = True

    def __init__(self) -> None:
        self.queue = asyncio.Queue()

    async def called_with(self, function: str, *args: object) -> None:
        assert (function, args) == await self.queue.get()

    async def called(self, expected_function: str) -> 'tuple[object, ...]':
        function, args = await self.queue.get()
        assert function == expected_function
        return args

    async def no_calls(self) -> None:
        for _ in range(10):
            await asyncio.sleep(0.001)
            assert self.queue.qsize() == 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.queue.put_nowait(('connection_made', (transport,)))

    def connection_lost(self, exc: 'Exception | None') -> None:
        self.queue.put_nowait(('connection_lost', (exc,)))

    def data_received(self, data: bytes) -> None:
        self.queue.put_nowait(('data_received', (data,)))

    def eof_received(self) -> bool:
        self.queue.put_nowait(('eof_received', ()))
        return self.eof_result

    def pause_writing(self) -> None:
        self.queue.put_nowait(('pause_writing', ()))

    def resume_writing(self) -> None:
        self.queue.put_nowait(('resume_writing', ()))


class RaiseResponder(ferny.AskpassHandler):
    async def do_askpass(self, messages: str, prompt: str, hint: str) -> None:
        raise ValueError('bzzt')


@pytest.mark.asyncio
async def test_enoent() -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['/nonexistent'])
    exc, = await protocol.called('connection_lost')
    assert isinstance(exc, FileNotFoundError)
    await protocol.no_calls()


@pytest.mark.asyncio
async def test_true() -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['true'])
    await protocol.called_with('connection_made', transport)
    assert isinstance(transport.get_extra_info('subprocess'), subprocess.Popen)
    assert transport.get_pid() not in (0, -1)
    await protocol.called_with('eof_received')
    await protocol.called_with('connection_lost', None)
    assert transport.get_returncode() == 0
    await protocol.no_calls()


@pytest.mark.asyncio
async def test_false() -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['false'])
    await protocol.called_with('connection_made', transport)
    await protocol.called_with('eof_received')
    await protocol.called_with('connection_lost', SubprocessError(1, ''))
    await protocol.no_calls()


@pytest.mark.asyncio
async def test_eof_returns_false() -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['false'])
    protocol.eof_result = False  # close immediately on EOF → ignores the cause
    await protocol.called_with('connection_made', transport)
    await protocol.called_with('eof_received')
    await protocol.called_with('connection_lost', None)
    await protocol.no_calls()


@pytest.mark.asyncio
async def test_immediate_close() -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['true'])
    assert isinstance(transport, ferny.FernyTransport)
    assert isinstance(protocol, MockProtocol)
    transport.close()
    await protocol.called_with('connection_lost', None)
    await protocol.no_calls()

    # repeated closes shouldn't hurt anything
    transport.close()
    await protocol.no_calls()


@pytest.mark.asyncio
async def test_use_before_ready() -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['true'])
    with pytest.raises(AssertionError):
        # we can't do this because we didn't get connection_made() yet
        transport.write(b'xxx')
    transport.close()
    await protocol.called_with('connection_lost', None)
    await protocol.no_calls()


@pytest.mark.asyncio
async def test_cat() -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['cat'])
    await protocol.called_with('connection_made', transport)
    transport.write(b'hihi')
    await protocol.called_with('data_received', b'hihi')

    # try switching protocols.  Should produce no calls.
    assert transport.get_protocol() is protocol
    new_protocol = MockProtocol()
    transport.set_protocol(new_protocol)
    await protocol.no_calls()
    await new_protocol.no_calls()
    assert transport.get_protocol() is new_protocol

    # continue with the new protocol
    transport.write(b'byebye')
    await new_protocol.called_with('data_received', b'byebye')

    # shutdown
    assert transport.get_returncode() is None
    assert transport.can_write_eof()
    transport.write_eof()
    await new_protocol.called_with('eof_received')
    await new_protocol.called_with('connection_lost', None)
    assert transport.get_returncode() == 0
    await new_protocol.no_calls()
    await protocol.no_calls()


@pytest.mark.asyncio
async def test_dead_cat() -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['cat'])
    assert await protocol.queue.get() == ('connection_made', (transport,))
    transport.terminate()
    await protocol.called_with('eof_received')
    await protocol.called_with('connection_lost', SubprocessError(-signal.SIGTERM, ''))
    await protocol.no_calls()

    # these should all fail now
    with pytest.raises(ProcessLookupError):
        transport.kill()
    with pytest.raises(ProcessLookupError):
        transport.terminate()
    with pytest.raises(ProcessLookupError):
        transport.send_signal(9)


@pytest.mark.asyncio
async def test_broken_pipe() -> None:
    script = 'echo xyz >&2; read a; exec sleep inf < /dev/null'
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['sh', '-c', script])
    assert await protocol.queue.get() == ('connection_made', (transport,))

    # Now we have to make sure that we do everything with blocking IO to ensure
    # that we don't have a chance to notice that the stdin pipe has closed
    # until write() fails with EPIPE.

    # First: this will cause `read` to exit.
    transport.write(b'close\n')
    # Now the shell will close its stdin (because of the </dev/null redirection).
    # Wait until the read end of the pipe closes.  We can observe that on the
    # write end of a pipe by polling for readability.  We want to avoid
    # returning to the main loop here to ensure that the first thing to observe
    # the closed pipe is the write() call, which will get EPIPE.
    assert transport._stdin_transport is not None
    stdin_pipe = transport._stdin_transport.get_extra_info('pipe')
    assert select.select([stdin_pipe.fileno()], [], [], 10000) != ([], [], [])

    # this is going to fail now.
    transport.write(b'x')
    assert transport._stdin_transport.is_closing()

    # ... but that's not reason enough to shut down the protocol ...
    await protocol.no_calls()
    assert not transport.is_closing()

    # now let's make sure we can get a different error reported
    transport.kill()
    await protocol.called_with('eof_received')
    await protocol.called_with('connection_lost', SubprocessError(-signal.SIGKILL, 'xyz\n'))
    await protocol.no_calls()


@pytest.mark.asyncio
async def test_ssh_error() -> None:
    # this should be treated as an error thrown by ssh
    script = 'exec ssh -p 1 127.0.0.1'  # hopefully nobody listens on port 1
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['sh', '-c', script], is_ssh=True)
    await protocol.called_with('connection_made', transport)
    await protocol.called_with('eof_received')
    exc, = await protocol.called('connection_lost')
    assert isinstance(exc, ConnectionRefusedError)


@pytest.mark.asyncio
async def test_not_ssh_error() -> None:
    # ...but if the error code is not 255, it's not an ssh error
    script = 'ssh -p 1 127.0.0.1; exit 25'  # hopefully nobody listens on port 1
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['sh', '-c', script], is_ssh=True)
    await protocol.called_with('connection_made', transport)
    await protocol.called_with('eof_received')
    exc, = await protocol.called('connection_lost')
    assert isinstance(exc, ferny.SubprocessError)
    assert exc.returncode == 25
    assert os.strerror(errno.ECONNREFUSED) in exc.stderr


@pytest.mark.asyncio
async def test_askpass_exception() -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, [ferny.interaction_client.__file__, 'x'],
                                                     interaction_handlers=(RaiseResponder(),))
    await protocol.called_with('connection_made', transport)
    exc, = await protocol.called('connection_lost')
    assert isinstance(exc, ValueError)
    assert exc.args == ('bzzt',)


def test_no_running_loop(event_loop: asyncio.AbstractEventLoop) -> None:
    with pytest.raises(RuntimeError, match='no running event loop'):
        if sys.version_info < (3, 7, 0):
            # 3.6 lacks asyncio.get_running_loop() and our fill for it will
            # create a loop, even if one isn't running
            raise RuntimeError('no running event loop')
        ferny.FernyTransport.spawn(MockProtocol, ['true'])

    # ...but we can pass one in
    transport, _protocol = ferny.FernyTransport.spawn(MockProtocol, ['true'], loop=event_loop)
    transport.close()

    # If we quit now, we'll see this:
    "sys:1: RuntimeWarning: coroutine 'BaseEventLoop.subprocess_exec' was never awaited"
    # Which is true, of course, but you don't normally need to await cancelled
    # tasks... The issue is: although we called .cancel() on the exec_task, the
    # cancellation never had a chance to occur, because the task didn't get a
    # chance to run yet:
    assert not transport._exec_task.cancelled()
    # If we run the mainloop for an iteration or two it'll work its way through...
    event_loop.run_until_complete(asyncio.sleep(0.1))
    assert transport._exec_task.cancelled()
    # There doesn't seem to be a better way to avoid this issue...


@pytest.mark.asyncio
async def test_bogus_write() -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['sleep', '10'])
    await protocol.called_with('connection_made', transport)

    # There's not a lot that can go wrong with pipes... and EPIPE is one thing
    # that we already filter out (and test).  Let's get evil.
    # Note: this is probably undefined with respect to epoll, but we'll avoid
    # returning to the mainloop in between.
    assert transport._stdin_transport is not None
    write_fd = transport._stdin_transport.get_extra_info('pipe').fileno()
    with open('/dev/null', 'rb') as devnull_readable:
        os.dup2(devnull_readable.fileno(), write_fd)
    transport.write(b'xyz')  # write() to readonly fd -> EBADF
    exc, = await protocol.called('connection_lost')
    assert isinstance(exc, OSError)
    assert exc.errno == errno.EBADF


@pytest.mark.asyncio
async def test_flow_control() -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['cat'])
    await protocol.called_with('connection_made', transport)

    # send some blocks through and fetch them immediately
    block = b'x' * 4096
    for _ in range(10):
        transport.write(block)
        # should arrive on the other end atomically
        await protocol.called_with('data_received', block)
        # should never buffer
        assert transport.get_write_buffer_size() == 0

    # disable userspace buffering
    assert transport.get_write_buffer_limits() != (0, 0)
    transport.set_write_buffer_limits(0)
    assert transport.get_write_buffer_limits() == (0, 0)

    # stop reading from the read end
    outstanding = 0
    assert transport.is_reading()
    transport.pause_reading()
    assert not transport.is_reading()
    block = b'x' * 4096
    transport.writelines([block] * 100)
    outstanding += len(block) * 100
    # that should have definitely backed up into userspace
    assert transport.get_write_buffer_size() > 0
    # and we should have heard about it on the write end
    await protocol.called_with('pause_writing')

    # let's start draining it.  this is a bit tricky.  the resume_writing()
    # call will appear at some point but it depends on timing.  just make sure
    # we get everything in the end.
    assert not transport.is_reading()
    transport.resume_reading()
    assert transport.is_reading()
    writing_resumed = False
    while outstanding or not writing_resumed:
        func, args = await protocol.queue.get()
        if func == 'data_received':
            assert isinstance(args[0], bytes)
            outstanding -= len(args[0])
        else:
            assert func == 'resume_writing'
            writing_resumed = True

    # again: send some blocks through and fetch them immediately
    block = b'x' * 4096
    for _ in range(10):
        transport.write(block)
        # should never buffer
        await protocol.called_with('data_received', block)
        assert transport.get_write_buffer_size() == 0

    # let's finish up
    transport.write_eof()
    await protocol.called_with('eof_received')
    await protocol.called_with('connection_lost', None)


@pytest.mark.asyncio
async def test_eof_buffered(tmp_path: Path, event_loop: asyncio.AbstractEventLoop) -> None:
    pipe = str(tmp_path / 'fifo')
    os.mkfifo(pipe)
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['dd', 'bs=1k', f'of={pipe}'])
    await protocol.called_with('connection_made', transport)

    # write lots of 'x' followed by 'y', which will buffer and eventually complain
    transport.set_write_buffer_limits(0)
    transport.writelines([b'x' * 4096] * 10000 + [b'y'])
    await protocol.called_with('pause_writing')
    transport.write_eof()
    await protocol.no_calls()

    # we should now be able to read that all back, with the EOF.
    with open(pipe, 'rb') as reader:
        all_data = await event_loop.run_in_executor(None, reader.read)
    assert len(all_data) == 10000 * 4096 + 1
    assert all_data.endswith(b'y')

    # close things up
    transport.close()
    await protocol.called_with('eof_received')
    # it's weird that we get resume_writing after we called write_eof() but I
    # guess once the buffer empties, logically, it kinda makes sense?  In any
    # case, that's coming from SubprocessTransport, so it's not for us to
    # decide.
    await protocol.called_with('resume_writing')
    await protocol.called_with('connection_lost', None)
    await protocol.no_calls()


# Make sure .close() works properly even with a backed up buffer.
# This is tricky: the Transport docs suggest that .close() should first try to
# flush the buffer, but SubprocessTransport.close() immediately kills the
# subprocess.  We might change this.
@pytest.mark.asyncio
async def test_close_buffered(event_loop: asyncio.AbstractEventLoop) -> None:
    transport, protocol = ferny.FernyTransport.spawn(MockProtocol, ['sleep', 'inf'])
    await protocol.called_with('connection_made', transport)

    # write lots of 'x'.  these will never be read (by sleep)
    transport.set_write_buffer_limits(0)
    transport.writelines([b'x' * 4096] * 100)
    await protocol.called_with('pause_writing')
    transport.close()
    # make sure we shut down immediately, without the buffer draining
    await protocol.called_with('connection_lost', None)
