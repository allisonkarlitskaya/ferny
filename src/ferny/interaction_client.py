#!/usr/bin/python3

import array
import os
import socket
import sys


def interact(stdout_fd: int, stderr_fd: int, *data: object) -> int:
    packet = f'\0ferny\0{repr(data)}'.encode('utf-8')

    ours, theirs = socket.socketpair()

    with theirs, socket.fromfd(stderr_fd, socket.AF_UNIX, socket.SOCK_STREAM) as stderr:
        # socket.send_fds(stderr, [packet], [theirs.fileno(), stdout_fd])
        fds = [theirs.fileno(), stdout_fd]
        stderr.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])

    with ours:
        return int(ours.recv(16) or b'1')


def main() -> None:
    sys.exit(interact(sys.stdout.fileno(), sys.stderr.fileno(), sys.argv, dict(os.environ)))


if __name__ == '__main__':
    main()
