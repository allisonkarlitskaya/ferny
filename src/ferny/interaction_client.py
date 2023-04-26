#!/usr/bin/python3

import array
import os
import select
import socket
import sys


def interact(stdin_fd: int, stdout_fd: int, stderr_fd: int, *data: object) -> int:
    packet = f'\0ferny\0{repr(data)}'.encode('utf-8')

    ours, theirs = socket.socketpair()

    with theirs, socket.fromfd(stderr_fd, socket.AF_UNIX, socket.SOCK_STREAM) as stderr:
        # socket.send_fds(stderr, [packet], [theirs.fileno(), stdout_fd])
        fds = [theirs.fileno(), stdout_fd]
        stderr.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])

    # check if stdin is an actual communication channel, as opposed to e.g. /dev/null which is immediately EOF
    res = select.select([stdin_fd], [], [], 0)[0]
    if stdin_fd in res:
        try:
            have_stdin = os.read(stdin_fd, 1) != b''
        except OSError:
            have_stdin = False
    else:
        have_stdin = True

    with ours:
        # wait until we either get a result on ours, or the caller closes stdin to signal cancelling
        ready = select.select([stdin_fd, ours], [], [])
        if not have_stdin or ours in ready[0]:
            return int(ours.recv(16) or b'1')
        else:
            return 1


def main() -> None:
    sys.exit(interact(sys.stdin.fileno(), sys.stdout.fileno(), sys.stderr.fileno(), sys.argv, dict(os.environ)))


if __name__ == '__main__':
    main()
