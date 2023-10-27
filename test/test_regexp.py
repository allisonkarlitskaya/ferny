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
import subprocess
import sys
import textwrap

import pytest

import ferny

# Actual messages seen in the wild, for documentation and testing
ASKPASS_MESSAGES: 'dict[str, tuple[str, str, dict[str, str]]]' = {
    'new host': (
        r"""The authenticity of host 'github.com (140.82.121.3)' can't be established.
        ED25519 key fingerprint is SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.
        This key is not known by any other names
        Are you sure you want to continue connecting (yes/no/[fingerprint])? """,
        'SshHostKeyPrompt', {
            'algorithm': 'ED25519',
            'fingerprint': 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU',
        }
    ),

    'new host name': (
        r"""The authenticity of host 'github.com (140.82.121.3)' can't be established.
        ED25519 key fingerprint is SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU.
        This host key is known by the following other names/addresses:
            x:1: example.com
        Are you sure you want to continue connecting (yes/no/[fingerprint])? """,
        'SshHostKeyPrompt', {
            'algorithm': 'ED25519',
            'fingerprint': 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU',
        }
    ),

    'passphrase': (
        r"""Enter passphrase for key '/var/home/lis/.ssh/id_rsa': """,
        'SshPassphrasePrompt', {
            'filename': '/var/home/lis/.ssh/id_rsa',
        }
    ),

    'password': (
        r"""lis@srv's password: """,
        'SshPasswordPrompt', {
            'username': 'lis',
            'hostname': 'srv',
        }
    ),

    'FIDO PIN': (
        r"""Enter PIN for ED25519-SK key /var/home/lis/.ssh/id_ed25519_sk: """,
        'SshFIDOPINPrompt', {
            'algorithm': 'ED25519-SK',
            'filename': '/var/home/lis/.ssh/id_ed25519_sk',
        }
    ),

    'User presence': (
        r"""Confirm user presence for key ED25519-SK SHA256:fAxxFFykCijTdrVUUjbbi2TWfCWtOiafhuBhgG7siGg""",
        'SshFIDOUserPresencePrompt', {
            'algorithm': 'ED25519-SK',
            'fingerprint': 'SHA256:fAxxFFykCijTdrVUUjbbi2TWfCWtOiafhuBhgG7siGg',
        }
    ),

    'change pw old': (
        r"""Enter lis@srv's old password: """,
        'AskpassPrompt', {
        }
    ),

    'change pw new': (
        r"""Enter lis@srv's new password: """,
        'AskpassPrompt', {
        }
    ),

    'change pw verify': (
        r"""Retype lis@srv's new password: """,
        'AskpassPrompt', {
        }
    ),

    'SshPKCS11PINPrompt': (
        r"""Enter PIN for '/CN=SSH-key/': """,
        'SshPKCS11PINPrompt', {
            'pkcs11_id': '/CN=SSH-key/',
        }
    ),

    'joshua': (
        r"""A strange game.
        The only winning move is
        not to play.

        How about a nice game of chess?
        """,
        'AskpassPrompt', {
            'prompt': 'How about a nice game of chess?\n',
        }
    ),
}


STDERR_MESSAGES = {
    'SshChangedHostKeyError': r"""
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

    'SshUnknownHostKeyError': r"""
    No ED25519 host key is known for srv and you have requested strict checking.
    Host key verification failed.
    """,

    # 'StrictHostKeyChecking=no (unsupported)': r"""
    # Password authentication is disabled to avoid man-in-the-middle attacks.
    # Keyboard-interactive authentication is disabled to avoid man-in-the-middle attacks.
    # lis@github.com: Permission denied (publickey).
    # """,

    'SshAuthenticationError': r"""
    xyz@srv: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).
    """,

    'SshError': r"""Something bad happened.
    """,
}


@pytest.mark.parametrize('msg_id', ASKPASS_MESSAGES)
def test_categorize_askpass(msg_id: str) -> None:
    message, expected_type, expected_attrs = ASKPASS_MESSAGES[msg_id]
    message = message.replace('\n        ', '\n')  # dedent

    # categorize the prompt
    prompt = ferny.ssh_askpass.categorize_ssh_prompt(message, '')

    # confirm the expected type
    assert prompt.__class__.__name__ == expected_type
    # confirm prompt is non-empty
    assert prompt.prompt != ''
    # confirm prompt contains no newlines except (optional) one trailing
    assert '\n' not in prompt.prompt[:-1]
    # confirm messages is a series of complete lines
    assert prompt.messages.endswith('\n') or prompt.messages == ''
    # the messages plus the prompt should exactly equal the original
    assert prompt.messages + prompt.prompt == message
    # our expected attributes ought to be set
    assert dict(prompt.__dict__, ** expected_attrs) == prompt.__dict__
    # we passed '' for stderr, make sure it got set properly
    assert prompt.stderr == ''


@pytest.mark.parametrize('msg_id', STDERR_MESSAGES)
def test_categorize_errors(msg_id: str) -> None:
    expected_type = msg_id.split()[0]
    message = textwrap.dedent(STDERR_MESSAGES[msg_id])
    exc = ferny.ssh_errors.get_exception_for_ssh_stderr(message)
    assert exc.__class__.__name__ == expected_type


class MockResponder(ferny.SshAskpassResponder):
    async def do_prompt(self, prompt: ferny.AskpassPrompt) -> 'str | None':
        # respond with the type of the prompt
        assert prompt.stderr == ''
        return prompt.__class__.__name__


@pytest.mark.parametrize('msg_id', ASKPASS_MESSAGES)
@pytest.mark.asyncio
async def test_mock_askpass(msg_id: str) -> None:
    message, expected_type, expected_attrs = ASKPASS_MESSAGES[msg_id]
    message = message.replace('\n        ', '\n')  # dedent

    # Spawn ferny-askpass to talk to a running agent which simply replies with
    # the name of the type of prompt object that was created.
    agent = ferny.InteractionAgent([MockResponder()])
    askpass_cmd = [sys.executable, ferny.interaction_client.__file__, message]
    askpass = subprocess.Popen(askpass_cmd, stderr=agent.fileno(), stdout=subprocess.PIPE, universal_newlines=True)

    # This will do one successful interaction and then exit with an error due
    # to 'unexpectedly' receiving EOF on stderr.
    with pytest.raises(ferny.InteractionError):
        await agent.communicate()

    # ferny-askpass ought to have received the response from MockResponder
    # which should be the name of the type of the prompt.
    stdout, stderr = askpass.communicate()
    assert stdout == f'{expected_type}\n'
    assert stderr is None


@pytest.mark.parametrize('msg_id', STDERR_MESSAGES)
@pytest.mark.asyncio
async def test_mock_stderr(msg_id: str) -> None:
    expected_type = msg_id.split()[0]
    message = textwrap.dedent(STDERR_MESSAGES[msg_id])

    # Spawn ferny-askpass to talk to a running agent which simply replies with
    # the name of the type of prompt object that was created.
    agent = ferny.InteractionAgent([MockResponder()])
    os.write(agent.fileno(), message.encode())

    with pytest.raises(ferny.SshError) as ssh_exc:
        # Until we get a better API, you have to do this, unfortunately:
        try:
            await agent.communicate()
        except ferny.InteractionError as int_exc:
            raise ferny.ssh_errors.get_exception_for_ssh_stderr(str(int_exc)) from None

    assert ssh_exc.value.__class__.__name__ == expected_type
