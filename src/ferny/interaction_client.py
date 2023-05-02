#!/usr/bin/python3

import array
import io
import os
import socket
import sys

from typing import Dict, List, Sequence


def command(stderr_fd: int, command: str, *args: object, fds: Sequence[int] = ()) -> None:
    cmd_read, cmd_write = [io.open(*end) for end in zip(os.pipe(), 'rw')]

    with cmd_write:
        with cmd_read:
            with socket.fromfd(stderr_fd, socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                fd_array = array.array('i', (cmd_read.fileno(), *fds))
                sock.sendmsg([b'\0'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fd_array)])

        cmd_write.write(repr((command, args)))


def askpass(stderr_fd: int, stdout_fd: int, args: List[str], env: Dict[str, str]) -> int:
    ours, theirs = socket.socketpair()

    with theirs:
        command(stderr_fd, 'ferny.askpass', args, env, fds=(theirs.fileno(), stdout_fd))

    with ours:
        return int(ours.recv(16) or b'1')


def main() -> None:
    if len(sys.argv) == 1:
        command(2, 'ferny.end', [])
    else:
        sys.exit(askpass(2, 1, sys.argv, dict(os.environ)))


if __name__ == '__main__':
    main()
