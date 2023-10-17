import argparse
import asyncio
import logging
import os
from typing import NoReturn

from prompt_toolkit import PromptSession

import ferny


class PromptResponder(PromptSession, ferny.SshAskpassResponder):
    async def do_hostkey(self, reason: str, host: str, algorithm: str, key: str, fingerprint: str) -> bool:
        print(f'Host key {host} {fingerprint}')
        response = await self.prompt_async('Accept [yes/no/abort]? ')
        if response.lower() in ['a', 'abort']:
            raise RuntimeError('rejecting hostkey')
        return response.lower() in ['y', 'yes']

    async def do_fido_user_presence_prompt(self, prompt: ferny.SshFIDOUserPresencePrompt) -> NoReturn:
        print(prompt.stderr)
        try:
            print('--askpass-- (%s)', prompt.__class__.__name__)
            print(prompt.messages)
            print(prompt.prompt)
            print('[ waiting ]')
            # We need to wait around until our task gets cancelled
            while True:
                await asyncio.sleep(10)
        finally:
            print('- done ----')

    async def do_prompt(self, prompt: ferny.AskpassPrompt) -> str | None:
        print(prompt.stderr)
        try:
            print('--askpass-- (%s)', prompt.__class__.__name__)
            print(prompt.messages)
            assert '\n' not in prompt.prompt
            return await self.prompt_async(prompt.prompt, is_password=True)
        finally:
            print('- done ----')


class DumbProtocol(asyncio.Protocol):
    done: asyncio.Future[None]

    def __init__(self) -> None:
        self.done = asyncio.get_running_loop().create_future()

    def data_received(self, data: bytes) -> None:
        os.write(1, data)

    def eof_received(self) -> bool | None:
        print('- eof -----')
        return True

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None:
            self.done.set_exception(exc)
        else:
            self.done.set_result(None)


async def run() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', '-d', action='store_true')
    parser.add_argument('host')
    parser.add_argument('cmd', nargs='+')
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    env = dict(os.environ, SSH_ASKPASS=ferny.interaction_client.__file__)
    transport, protocol = ferny.transport.FernyTransport.spawn(DumbProtocol,
                                                               ['ssh', args.host, *args.cmd], env=env,
                                                               start_new_session=True,
                                                               interaction_handlers=[PromptResponder()])
    await protocol.done


def main() -> None:
    asyncio.run(run())


if __name__ == '__main__':
    main()
