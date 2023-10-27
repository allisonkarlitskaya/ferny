import logging
import re
from typing import ClassVar, Match, Sequence

from .interaction_agent import AskpassHandler

logger = logging.getLogger(__name__)


class AskpassPrompt:
    """An askpass prompt resulting from a call to ferny-askpass.

      stderr: the contents of stderr from before ferny-askpass was called.
              Likely related to previous failed operations.
      messages: all but the last line of the prompt as handed to ferny-askpass.
                Usually contains context about the question.
      prompt: the last line handed to ferny-askpass.  The prompt itself.
    """
    stderr: str
    messages: str
    prompt: str

    def __init__(self, prompt: str, messages: str, stderr: str) -> None:
        self.stderr = stderr
        self.messages = messages
        self.prompt = prompt

    def reply(self, response: str) -> None:
        pass

    def close(self) -> None:
        pass

    async def handle_via(self, responder: 'SshAskpassResponder') -> None:
        try:
            response = await self.dispatch(responder)
            if response is not None:
                self.reply(response)
        finally:
            self.close()

    async def dispatch(self, responder: 'SshAskpassResponder') -> 'str | None':
        return await responder.do_prompt(self)


class SSHAskpassPrompt(AskpassPrompt):
    # The valid answers to prompts of this type.  If this is None then any
    # answer is permitted.  If it's a sequence then only answers from the
    # sequence are permitted.  If it's an empty sequence, then no answer is
    # permitted (ie: the askpass callback should never return).
    answers: 'ClassVar[Sequence[str] | None]' = None

    # Patterns to capture.  `_pattern` *must* match.
    _pattern: ClassVar[str]
    # `_extra_patterns` can fill in extra class attributes if they match.
    _extra_patterns: ClassVar[Sequence[str]] = ()

    def __init__(self, prompt: str, messages: str, stderr: str, match: Match) -> None:
        super().__init__(prompt, messages, stderr)
        self.__dict__.update(match.groupdict())

        for pattern in self._extra_patterns:
            extra_match = re.search(with_helpers(pattern), messages, re.M)
            print(extra_match, with_helpers(pattern), messages)
            if extra_match is not None:
                self.__dict__.update(extra_match.groupdict())


# Specific prompts
HELPERS = {
    "%{algorithm}": r"(?P<algorithm>\b[-\w]+\b)",
    "%{filename}": r"(?P<filename>.+)",
    "%{fingerprint}": r"(?P<fingerprint>SHA256:[0-9A-Za-z+/]{43})",
    "%{hostname}": r"(?P<hostname>[^ @']+)",
    "%{pkcs11_id}": r"(?P<pkcs11_id>.+)",
    "%{username}": r"(?P<username>[^ @']+)",
}


class SshPasswordPrompt(SSHAskpassPrompt):
    _pattern = r"%{username}@%{hostname}'s password: "
    username: 'str | None' = None
    hostname: 'str | None' = None

    async def dispatch(self, responder: 'SshAskpassResponder') -> 'str | None':
        return await responder.do_password_prompt(self)


class SshPassphrasePrompt(SSHAskpassPrompt):
    _pattern = r"Enter passphrase for key '%{filename}': "
    filename: str

    async def dispatch(self, responder: 'SshAskpassResponder') -> 'str | None':
        return await responder.do_passphrase_prompt(self)


class SshFIDOPINPrompt(SSHAskpassPrompt):
    _pattern = r"Enter PIN for %{algorithm} key %{filename}: "
    algorithm: str
    filename: str

    async def dispatch(self, responder: 'SshAskpassResponder') -> 'str  | None':
        return await responder.do_fido_pin_prompt(self)


class SshFIDOUserPresencePrompt(SSHAskpassPrompt):
    _pattern = r"Confirm user presence for key %{algorithm} %{fingerprint}"
    answers = ()
    algorithm: str
    fingerprint: str

    async def dispatch(self, responder: 'SshAskpassResponder') -> 'str | None':
        return await responder.do_fido_user_presence_prompt(self)


class SshPKCS11PINPrompt(SSHAskpassPrompt):
    _pattern = r"Enter PIN for '%{pkcs11_id}': "
    pkcs11_id: str

    async def dispatch(self, responder: 'SshAskpassResponder') -> 'str | None':
        return await responder.do_pkcs11_pin_prompt(self)


class SshHostKeyPrompt(SSHAskpassPrompt):
    _pattern = r"Are you sure you want to continue connecting \(yes/no(/\[fingerprint\])?\)\? "
    _extra_patterns = [
        r"%{fingerprint}[.]$",
        r"^%{algorithm} key fingerprint is",
        r"^The fingerprint for the %{algorithm} key sent by the remote host is$"
    ]
    answers = ('yes', 'no')
    algorithm: str
    fingerprint: str

    async def dispatch(self, responder: 'SshAskpassResponder') -> 'str | None':
        return await responder.do_host_key_prompt(self)


def with_helpers(pattern: str) -> str:
    for name, helper in HELPERS.items():
        pattern = pattern.replace(name, helper)

    assert '%{' not in pattern
    return pattern


def categorize_ssh_prompt(string: str, stderr: str) -> AskpassPrompt:
    classes = [
        SshFIDOPINPrompt,
        SshFIDOUserPresencePrompt,
        SshHostKeyPrompt,
        SshPKCS11PINPrompt,
        SshPassphrasePrompt,
        SshPasswordPrompt,
    ]

    # The last line is the line after the last newline character, excluding the
    # optional final newline character.  eg: "x\ny\nLAST\n" or "x\ny\nLAST"
    second_last_newline = string.rfind('\n', 0, -1)
    if second_last_newline >= 0:
        last_line = string[second_last_newline + 1:]
        extras = string[:second_last_newline + 1]
    else:
        last_line = string
        extras = ''

    for cls in classes:
        pattern = with_helpers(cls._pattern)
        match = re.fullmatch(pattern, last_line)
        if match is not None:
            return cls(last_line, extras, stderr, match)

    return AskpassPrompt(last_line, extras, stderr)


class SshAskpassResponder(AskpassHandler):
    async def do_askpass(self, stderr: str, prompt: str, hint: str) -> 'str | None':
        return await categorize_ssh_prompt(prompt, stderr).dispatch(self)

    async def do_prompt(self, prompt: AskpassPrompt) -> 'str | None':
        # Default fallback for unrecognised message types: unimplemented
        return None

    async def do_fido_pin_prompt(self, prompt: SshFIDOPINPrompt) -> 'str | None':
        return await self.do_prompt(prompt)

    async def do_fido_user_presence_prompt(self, prompt: SshFIDOUserPresencePrompt) -> 'str | None':
        return await self.do_prompt(prompt)

    async def do_host_key_prompt(self, prompt: SshHostKeyPrompt) -> 'str | None':
        return await self.do_prompt(prompt)

    async def do_pkcs11_pin_prompt(self, prompt: SshPKCS11PINPrompt) -> 'str | None':
        return await self.do_prompt(prompt)

    async def do_passphrase_prompt(self, prompt: SshPassphrasePrompt) -> 'str | None':
        return await self.do_prompt(prompt)

    async def do_password_prompt(self, prompt: SshPasswordPrompt) -> 'str | None':
        return await self.do_prompt(prompt)
