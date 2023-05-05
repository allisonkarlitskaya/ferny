import asyncio
import os
import sys

import pytest

import ferny


class SpeakSlow(ferny.InteractionResponder):
    running = False

    async def do_askpass(self, messages, prompt, hint):
        assert messages == 'warning: it works\n'
        assert prompt == 'can has pw?'
        assert hint == ''

        try:
            self.running = True
            await asyncio.sleep(10000)
            assert False, 'We should have been cancelled'
        finally:
            self.running = False


@pytest.mark.asyncio
async def test_cancel_askpass(event_loop):
    speak_slow = SpeakSlow()
    agent = ferny.InteractionAgent(speak_slow)
    process = await asyncio.create_subprocess_shell(
        r'''
            # log an error to stderr
            echo 'warning: it works' >&2

            # askpass interaction
            python3 -m ferny.askpass 'can has pw?' &

            # wait a moment
            sleep 0.5

            # kill askpass
            kill %1

            # log an error
            echo 'we killed askpass' >&2
        ''',
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=agent, env=dict(os.environ, PYTHONPATH=':'.join(sys.path)))

    with pytest.raises(ferny.InteractionError) as raises:
        await agent.communicate()
    assert raises.value.args == ('we killed askpass',)

    assert not speak_slow.running
    await process.wait()


@pytest.mark.asyncio
async def test_cancel_agent_during_interaction(event_loop):
    speak_slow = SpeakSlow()
    agent = ferny.InteractionAgent(speak_slow)
    process = await asyncio.create_subprocess_shell(
        r'''
            # log an error to stderr
            echo 'warning: it works' >&2

            # askpass interaction
            python3 -m ferny.askpass 'can has pw?'
        ''',
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=agent, env=dict(os.environ, PYTHONPATH=':'.join(sys.path)))

    # Communicate in a task
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
async def test_cancel_agent_on_init(event_loop):
    speak_slow = SpeakSlow()
    agent = ferny.InteractionAgent(speak_slow)
    process = await asyncio.create_subprocess_shell(
        r'''
            # log an error to stderr
            echo 'warning: it works' >&2

            # send "init" on stdout to inform that we're connected
            echo 'init'
        ''',
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=agent, env=dict(os.environ, PYTHONPATH=':'.join(sys.path)))

    # Communicate in a task
    communicate_task = event_loop.create_task(agent.communicate())

    # Wait until we got our "init"
    await process.stdout.readline() == b'init\n'

    # Cancel the interaction
    communicate_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await communicate_task

    await process.wait()


@pytest.mark.asyncio
@pytest.mark.xfail
async def test_cancel_before_interaction(event_loop):
    speak_slow = SpeakSlow()
    agent = ferny.InteractionAgent(speak_slow)
    process = await asyncio.create_subprocess_shell(
        r'''
            # wait a moment for the race
            sleep 0.1

            # askpass interaction
            python3 -m ferny.askpass 'can has pw?'
        ''',
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=agent, env=dict(os.environ, PYTHONPATH=':'.join(sys.path)))

    # Communicate in a task
    communicate_task = event_loop.create_task(agent.communicate())

    # Let the task start running
    await asyncio.sleep(0.01)

    # Cancel the interaction
    communicate_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await communicate_task

    # Drop the agent to close its fd
    # XXX: ideally, this wouldn't be necessary...
    # del agent

    # Make sure the subprocess cleanly exits and doesn't get stuck
    await asyncio.wait_for(process.wait(), 5)
