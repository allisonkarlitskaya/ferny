import asyncio
import os
import sys

import pytest

import ferny


class SpeakSlow(ferny.SshAskpassResponder):
    running = False

    async def do_askpass(self, messages: str, prompt: str, hint: str) -> None:
        assert messages == 'warning: it works\n'
        assert prompt == 'can has pw?'
        assert hint == ''

        try:
            self.running = True
            await asyncio.sleep(10000)
            pytest.fail('We should have been cancelled')
        finally:
            self.running = False


@pytest.mark.asyncio
async def test_cancel_askpass() -> None:
    speak_slow = SpeakSlow()
    agent = ferny.InteractionAgent([speak_slow])
    process = await asyncio.create_subprocess_shell(
        r'''
            # log an error to stderr
            echo 'warning: it works' >&2

            # askpass interaction
            python3 -m ferny.askpass 'can has pw?' &
            ASKPASS_PID=$!

            # wait a moment
            sleep 0.5

            # kill askpass
            kill $ASKPASS_PID

            # log an error
            echo 'we killed askpass' >&2
        ''',
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=agent.fileno(),
        env=dict(os.environ, PYTHONPATH=':'.join(sys.path)))

    with pytest.raises(ferny.InteractionError) as raises:
        await agent.communicate()
    assert raises.value.args == ('we killed askpass',)

    assert not speak_slow.running
    await process.wait()


@pytest.mark.asyncio
async def test_cancel_agent_during_interaction() -> None:
    speak_slow = SpeakSlow()
    agent = ferny.InteractionAgent([speak_slow])
    process = await asyncio.create_subprocess_shell(
        r'''
            # log an error to stderr
            echo 'warning: it works' >&2

            # askpass interaction
            python3 -m ferny.askpass 'can has pw?'
        ''',
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=agent.fileno(),
        env=dict(os.environ, PYTHONPATH=':'.join(sys.path)))

    # Communicate in a task
    event_loop = asyncio.get_running_loop()
    communicate_task = event_loop.create_task(agent.communicate())

    # Wait until we got our prompt
    while not speak_slow.running:
        await asyncio.sleep(0.05)

    # Cancel the interaction
    communicate_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await communicate_task

    await process.wait()


@pytest.mark.asyncio
async def test_cancel_agent_on_init() -> None:
    speak_slow = SpeakSlow()
    agent = ferny.InteractionAgent([speak_slow])
    process = await asyncio.create_subprocess_shell(
        r'''
            # log an error to stderr
            echo 'warning: it works' >&2

            # send "init" on stdout to inform that we're connected
            echo 'init'
        ''',
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=agent.fileno(),
        env=dict(os.environ, PYTHONPATH=':'.join(sys.path)))

    # Communicate in a task
    event_loop = asyncio.get_running_loop()
    communicate_task = event_loop.create_task(agent.communicate())

    # Wait until we got our "init"
    assert process.stdout is not None
    assert await process.stdout.readline() == b'init\n'

    # Cancel the interaction
    communicate_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await communicate_task

    await process.wait()


@pytest.mark.asyncio
async def test_cancel_before_interaction() -> None:
    speak_slow = SpeakSlow()
    agent = ferny.InteractionAgent([speak_slow])
    process = await asyncio.create_subprocess_shell(
        r'''
            # wait a moment for the race
            sleep 0.1

            # askpass interaction
            python3 -m ferny.askpass 'can has pw?'
        ''',
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=agent.fileno(),
        env=dict(os.environ, PYTHONPATH=':'.join(sys.path)))

    # Communicate in a task
    event_loop = asyncio.get_running_loop()
    communicate_task = event_loop.create_task(agent.communicate())

    # Let the task start running
    await asyncio.sleep(0.01)

    # Cancel the interaction
    communicate_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await communicate_task

    # Make sure the subprocess cleanly exits and doesn't get stuck
    await process.wait()


class RaiseResponder(ferny.AskpassHandler):
    commands = ('ferny.askpass', 'bzzt')

    async def do_askpass(self, messages: str, prompt: str, hint: str) -> None:
        raise ValueError(messages, prompt, hint)

    async def do_custom_command(
        self, command: str, args: 'tuple[object, ...]', fds: 'list[int]', stderr: str
    ) -> None:
        raise ValueError(command, args, fds, stderr)


@pytest.mark.asyncio
async def test_temporary_askpass() -> None:
    agent = ferny.InteractionAgent([RaiseResponder()])

    with ferny.temporary_askpass() as askpass:
        process = await asyncio.create_subprocess_exec(askpass, 'can has pw?', stderr=agent.fileno())

        with pytest.raises(ValueError) as raises:
            await agent.communicate()
        assert raises.value.args == ('', 'can has pw?', '')

        await process.wait()

    # outside with:, should no longer exit
    assert not os.path.exists(askpass)


@pytest.mark.asyncio
async def test_command_template() -> None:
    agent = ferny.InteractionAgent([RaiseResponder()])
    process = await asyncio.create_subprocess_exec(
        'python3', '-c', '; '.join([
            "import sys",
            "command = 'bzzt'",
            "args = (1, 2, 3)",
            f"sys.stderr.write(f{ferny.COMMAND_TEMPLATE!r})"
        ]), stderr=agent.fileno(),
        env=dict(os.environ, PYTHONPATH=':'.join(sys.path)))
    with pytest.raises(ValueError) as raises:
        await agent.communicate()
    assert raises.value.args == ('bzzt', (1, 2, 3), [], '')
    await process.wait()
