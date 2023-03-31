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

import errno
import re
import socket
import os

from typing import ClassVar, Iterable, Match, Optional, Pattern, Tuple


class SshError(Exception):
    PATTERN: ClassVar[Pattern]

    def __init__(self, match: Optional[Match], stderr: str):
        super().__init__(match.group(0) if match is not None else stderr)
        self.stderr = stderr


class AuthenticationError(SshError):
    PATTERN = re.compile(r'^([^:]+): Permission denied \(([^()]+)\)\.$', re.M)

    def __init__(self, match: Match, stderr: str):
        super().__init__(match, stderr)
        self.destination = match.group(1)
        self.methods = match.group(2).split(',')
        self.message = match.group(0)


class HostKeyError(SshError):
    PATTERN = re.compile(r'^Host key verification failed.$', re.M)


# Functionality for mapping getaddrinfo()-family error messages to their
# equivalent Python exceptions.
def make_gaierror_map() -> Iterable[Tuple[str, int]]:
    import ctypes
    libc = ctypes.CDLL(None)
    libc.gai_strerror.restype = ctypes.c_char_p

    for key in dir(socket):
        if key.startswith('EAI_'):
            errnum = getattr(socket, key)
            yield libc.gai_strerror(errnum).decode('utf-8'), errnum


gaierror_map = dict(make_gaierror_map())


# Functionality for passing strerror() error messages to their equivalent
# Python exceptions.
# There doesn't seem to be an official API for turning an errno into the
# correct subtype of OSError, and the list that cpython uses is hidden fairly
# deeply inside of the implementation.  This is basically copied from the
# ADD_ERRNO() lines in _PyExc_InitState in cpython/Objects/exceptions.c
oserror_subclass_map = dict((errnum, cls) for cls, errnum in [
    (BlockingIOError, errno.EAGAIN),
    (BlockingIOError, errno.EALREADY),
    (BlockingIOError, errno.EINPROGRESS),
    (BlockingIOError, errno.EWOULDBLOCK),
    (BrokenPipeError, errno.EPIPE),
    (BrokenPipeError, errno.ESHUTDOWN),
    (ChildProcessError, errno.ECHILD),
    (ConnectionAbortedError, errno.ECONNABORTED),
    (ConnectionRefusedError, errno.ECONNREFUSED),
    (ConnectionResetError, errno.ECONNRESET),
    (FileExistsError, errno.EEXIST),
    (FileNotFoundError, errno.ENOENT),
    (IsADirectoryError, errno.EISDIR),
    (NotADirectoryError, errno.ENOTDIR),
    (InterruptedError, errno.EINTR),
    (PermissionError, errno.EACCES),
    (PermissionError, errno.EPERM),
    (ProcessLookupError, errno.ESRCH),
    (TimeoutError, errno.ETIMEDOUT),
])


def get_exception_for_ssh_stderr(stderr: str) -> Exception:
    for ssh_cls in [AuthenticationError, HostKeyError]:
        match = ssh_cls.PATTERN.search(stderr)
        if match is not None:
            return ssh_cls(match, stderr)

    before, colon, after = stderr.rpartition(':')
    if colon and after:
        potential_strerror = after.strip()

        # DNS lookup errors
        if potential_strerror in gaierror_map:
            errnum = gaierror_map[potential_strerror]
            return socket.gaierror(errnum, stderr)

        # Network connect errors
        for errnum in errno.errorcode:
            if os.strerror(errnum) == potential_strerror:
                os_cls = oserror_subclass_map.get(errnum, OSError)
                return os_cls(errnum, stderr)

    # No match?  Generic.
    return SshError(None, stderr)
