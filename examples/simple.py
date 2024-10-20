import argparse
import asyncio
import subprocess

from prompt_toolkit import PromptSession

import ferny


class PromptResponder(PromptSession, ferny.SshAskpassResponder):
    async def do_hostkey(self, reason: str, host: str, algorithm: str, key: str, fingerprint: str) -> bool:
        print(f'Host key {host} {fingerprint}')
        response = await self.prompt_async('Accept [yes/no/abort]? ')
        if response.lower() in ['a', 'abort']:
            raise RuntimeError('rejecting hostkey')
        return response.lower() in ['y', 'yes']

    async def do_askpass(self, messages: str, prompt: str, hint: str) -> str | None:
        print(messages)
        try:
            print('--askpass--')
            if hint == 'none':
                print(prompt)
                print('[ waiting ]')
                while True:
                    await asyncio.sleep(10)
                return None
            elif hint == 'confirm':
                # we should not see this from ssh(1)
                return await self.prompt_async(prompt)
            else:
                return await self.prompt_async(prompt, is_password=True)
        finally:
            print('-----------')


async def run() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int)
    parser.add_argument('host')
    parser.add_argument('cmd', nargs='+')
    args = parser.parse_args()

    session = ferny.Session()
    await session.connect(args.host, port=args.port, interaction_responder=PromptResponder())
    subprocess.run(session.wrap_subprocess_args(args.cmd), check=True)
    await session.disconnect()


def main() -> None:
    asyncio.run(run())


if __name__ == '__main__':
    main()
