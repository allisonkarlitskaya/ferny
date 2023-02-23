#!/usr/bin/python3

import os
import socket
import sys


def interact(stderr_fd: int, stdout_fd: int, *data: object) -> int:
    packet = f'\0ferny\0{repr(data)}'.encode('utf-8')

    ours, theirs = socket.socketpair()

    with theirs, socket.fromfd(stderr_fd, socket.AF_UNIX, socket.SOCK_STREAM) as stderr:
        socket.send_fds(stderr, [packet], [theirs.fileno(), stdout_fd])

    with ours:
        return int(ours.recv(16) or b'1')


def main() -> None:
    sys.exit(interact(2, 1, sys.argv, dict(os.environ)))


if __name__ == '__main__':
    main()
