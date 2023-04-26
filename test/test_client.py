import os
import socket
import threading

# for older Python versions
from ferny.interaction_agent import recv_fds
from ferny.interaction_client import interact


def test_basic():
    our_err, their_err = socket.socketpair()
    our_in, their_in = os.pipe()
    our_out, their_out = os.pipe()

    interact_res = None

    def run_interact():
        nonlocal interact_res
        interact_res = interact(their_in, their_out, their_err.fileno(), ['some', 'data'], {'answer': 42})

    t_interact = threading.Thread(target=run_interact)
    t_interact.start()
    os.close(their_out)

    # receive the two fds from the client
    msg, [res_fd, res_out], _flags, _addr = recv_fds(our_err, 4096, 2)
    their_err.close()

    # send result
    os.write(res_fd, b'7')
    os.close(res_fd)
    t_interact.join()

    assert msg == b"\x00ferny\x00(['some', 'data'], {'answer': 42})"
    assert interact_res == 7


def test_send_no_result():
    our_err, their_err = socket.socketpair()
    our_in, their_in = os.pipe()
    our_out, their_out = os.pipe()

    interact_res = None

    def run_interact():
        nonlocal interact_res
        interact_res = interact(their_in, their_out, their_err.fileno(), 'data')

    t_interact = threading.Thread(target=run_interact)
    t_interact.start()
    os.close(their_out)

    # receive the two fds from the client
    msg, [res_fd, _res_out], _flags, _addr = recv_fds(our_err, 4096, 2)
    their_err.close()

    # don't send a result
    os.close(res_fd)
    t_interact.join()

    assert msg == b"\x00ferny\x00('data',)"
    # default result is 1
    assert interact_res == 1


def test_exit_on_stdin_eof():
    our_err, their_err = socket.socketpair()
    our_in, their_in = os.pipe()
    our_out, their_out = os.pipe()

    interact_res = None

    def run_interact():
        nonlocal interact_res
        interact_res = interact(their_in, their_out, their_err.fileno(), 'data')

    t_interact = threading.Thread(target=run_interact)
    t_interact.start()
    os.close(their_out)

    # receive the two fds from the client
    _msg, [res_fd, _res_out], _flags, _addr = recv_fds(our_err, 4096, 2)
    their_err.close()

    # close stdin to indicate cancelling, don't send a result
    os.close(our_in)

    t_interact.join()

    assert interact_res == 1
