# ferny - asyncio SSH client library, using ssh(1)
#
# Copyright (C) 2022 Allison Karlitskaya <allison.karlitskaya@redhat.com>
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
import ctypes
import functools
import logging
import os
import shlex
import signal
import subprocess
import tempfile
from typing import Mapping, Sequence

from . import ssh_errors
from .interaction_agent import InteractionAgent, InteractionError, InteractionHandler, write_askpass_to_tmpdir

prctl = ctypes.cdll.LoadLibrary('libc.so.6').prctl
logger = logging.getLogger(__name__)
PR_SET_PDEATHSIG = 1


@functools.lru_cache()
def has_feature(feature: str, teststr: str = 'x') -> bool:
    try:
        subprocess.check_output(['ssh', f'-o{feature} {teststr}', '-G', 'nonexisting'], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


class SubprocessContext:
    def wrap_subprocess_args(self, args: Sequence[str]) -> Sequence[str]:
        """Return the args required to launch a process in the given context.

        For example, this might return a vector with
            ["sudo"]
        or
            ["flatpak-spawn", "--host"]
        prepended.

        It is also possible that more substantial changes may be performed.

        This function is not permitted to modify its argument, although it may
        (optionally) return it unmodified, if no changes are required.
        """
        return args

    def wrap_subprocess_env(self, env: Mapping[str, str]) -> Mapping[str, str]:
        """Return the envp required to launch a process in the given context.

        For example, this might set the "SUDO_ASKPASS" environment variable, if
        needed.

        As with wrap_subprocess_args(), this function is not permitted to
        modify its argument, although it may (optionally) return it unmodified
        if no changes are required.
        """
        return env


class Session(SubprocessContext, InteractionHandler):
    # Set after .connect() called, even if failed
    _controldir: 'tempfile.TemporaryDirectory | None' = None
    _controlsock: 'str | None' = None

    # Set if connected, else None
    _process: 'asyncio.subprocess.Process | None' = None

    async def connect(self,
                      destination: str,
                      handle_host_key: bool = False,
                      configfile: 'str | None' = None,
                      identity_file: 'str | None' = None,
                      login_name: 'str | None' = None,
                      options: 'Mapping[str, str] | None' = None,
                      pkcs11: 'str | None' = None,
                      port: 'int | None' = None,
                      interaction_responder: 'InteractionHandler | None' = None) -> None:
        rundir = os.path.join(os.environ.get('XDG_RUNTIME_DIR', '/run'), 'ferny')
        os.makedirs(rundir, exist_ok=True)
        self._controldir = tempfile.TemporaryDirectory(dir=rundir)
        self._controlsock = f'{self._controldir.name}/socket'

        # In general, we can't guarantee an accessible and executable version
        # of this file, but since it's small and we're making a temporary
        # directory anyway, let's just copy it into place and use it from
        # there.
        askpass_path = write_askpass_to_tmpdir(self._controldir.name)

        env = dict(os.environ)
        env['SSH_ASKPASS'] = askpass_path
        env['SSH_ASKPASS_REQUIRE'] = 'force'
        # old SSH doesn't understand SSH_ASKPASS_REQUIRE and guesses based on DISPLAY instead
        env['DISPLAY'] = '-'

        args = [
            '-M',
            '-N',
            '-S', self._controlsock,
            '-o', 'PermitLocalCommand=yes',
            '-o', f'LocalCommand={askpass_path}',
        ]

        if configfile is not None:
            args.append(f'-F{configfile}')

        if identity_file is not None:
            args.append(f'-i{identity_file}')

        if options is not None:
            for key in options:  # Note: Mapping may not have .items()
                args.append(f'-o{key} {options[key]}')

        if pkcs11 is not None:
            args.append(f'-I{pkcs11}')

        if port is not None:
            args.append(f'-p{port}')

        if login_name is not None:
            args.append(f'-l{login_name}')

        if handle_host_key and has_feature('KnownHostsCommand'):
            args.extend([
                '-o', f'KnownHostsCommand={askpass_path} %I %H %t %K %f',
                '-o', 'StrictHostKeyChecking=yes',
            ])

        agent = InteractionAgent([interaction_responder] if interaction_responder is not None else [])

        # SSH_ASKPASS_REQUIRE is not generally available, so use setsid
        process = await asyncio.create_subprocess_exec(
            *('/usr/bin/ssh', *args, destination), env=env,
            start_new_session=True, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL, stderr=agent,  # type: ignore
            preexec_fn=lambda: prctl(PR_SET_PDEATHSIG, signal.SIGKILL))

        # This is tricky: we need to clean up the subprocess, but only in case
        # if failure.  Otherwise, we keep it around.
        try:
            await agent.communicate()
            assert os.path.exists(self._controlsock)
            self._process = process
        except InteractionError as exc:
            await process.wait()
            raise ssh_errors.get_exception_for_ssh_stderr(str(exc)) from None
        except BaseException:
            # If we get here because the InteractionHandler raised an
            # exception then SSH might still be running, and may even attempt
            # further interactions (ie: 2nd attempt for password).  We already
            # have our exception and don't need any more info.  Kill it.
            try:
                process.kill()
            except ProcessLookupError:
                pass  # already exited?  good.
            await process.wait()
            raise

    def is_connected(self) -> bool:
        return self._process is not None

    async def wait(self) -> None:
        assert self._process is not None
        await self._process.wait()

    def exit(self) -> None:
        assert self._process is not None
        self._process.terminate()

    async def disconnect(self) -> None:
        self.exit()
        await self.wait()

    # Launching of processes
    def wrap_subprocess_args(self, args: Sequence[str]) -> Sequence[str]:
        assert self._controlsock is not None
        # 1. We specify the hostname as the empty string: it will be ignored
        #    when ssh is trying to use the control socket, but in case the
        #    socket has stopped working, ssh will try to fall back to directly
        #    connecting, in which case an empty hostname will prevent that.
        # 2. We need to quote the arguments — ssh will paste them together
        #    using only spaces, executing the result using the user's shell.
        return ('ssh', '-S', self._controlsock, '', *map(shlex.quote, args))
