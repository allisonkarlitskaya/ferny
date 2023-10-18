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

import os
import textwrap
from typing import Optional

import pytest

import ferny

# Actual messages seen in the wild, for documentation and testing
STDERR_MESSAGES = {
    'ChangedHostKeyError': r"""
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
    Someone could be eavesdropping on you right now (man-in-the-middle attack)!
    It is also possible that a host key has just been changed.
    The fingerprint for the ED25519 key sent by the remote host is
    SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.
    Please contact your system administrator.
    Add correct host key in x to get rid of this message.
    Offending ED25519 key in x:1
    Host key for github.com has changed and you have requested strict checking.
    Host key verification failed.
    """,

    'UnknownHostKeyError': r"""
    No ED25519 host key is known for srv and you have requested strict checking.
    Host key verification failed.
    """,

    # 'StrictHostKeyChecking=no (unsupported)': r"""
    # Password authentication is disabled to avoid man-in-the-middle attacks.
    # Keyboard-interactive authentication is disabled to avoid man-in-the-middle attacks.
    # lis@github.com: Permission denied (publickey).
    # """,

    'AuthenticationError': r"""
    xyz@srv: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).
    """,

    'SshError': r"""Something bad happened.
    """,
}


@pytest.mark.parametrize('msg_id', STDERR_MESSAGES)
def test_categorize_errors(msg_id: str) -> None:
    expected_type = msg_id.split()[0]
    message = textwrap.dedent(STDERR_MESSAGES[msg_id])
    exc = ferny.errors.get_exception_for_ssh_stderr(message)
    assert exc.__class__.__name__ == expected_type


class MockResponder(ferny.SshAskpassResponder):
    async def do_prompt(self, prompt: ferny.AskpassPrompt) -> Optional[str]:
        # respond with the type of the prompt
        assert prompt.stderr == ''
        return prompt.__class__.__name__


@pytest.mark.parametrize('msg_id', STDERR_MESSAGES)
@pytest.mark.asyncio
async def test_mock_stderr(msg_id: str) -> None:
    expected_type = msg_id.split()[0]
    message = textwrap.dedent(STDERR_MESSAGES[msg_id])

    # Spawn ferny-askpass to talk to a running agent which simply replies with
    # the name of the type of prompt object that was created.
    agent = ferny.InteractionAgent(MockResponder())
    os.write(agent.fileno(), message.encode())

    with pytest.raises(ferny.SshError) as ssh_exc:
        # Until we get a better API, you have to do this, unfortunately:
        try:
            await agent.communicate()
        except ferny.InteractionError as int_exc:
            raise ferny.errors.get_exception_for_ssh_stderr(str(int_exc)) from None

    assert ssh_exc.value.__class__.__name__ == expected_type
