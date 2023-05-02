# ferny "Interaction" protocol

ferny includes an askpass client program and agent.  The agent is implemented
as a class which runs as part of the Python program using ferny and the client
program is invoked as the `SSH_ASKPASS` program.

The interaction occurs via `stderr`.  Before `ssh` is spawned, a `socketpair()`
is created in the `AF_UNIX` domain, and one half of it is passed as the
`stderr` of the `ssh` authentication process.  At that point, the agent starts
attempting to receive messages on its end of the socket.

## Protocol details

This section is subject to change at absolutely any time.  You should only use
`ferny.InteractionAgent` and `ferny.interaction_client` found in the same
package.  Mixing and matching from different versions will likely break.
Implementing it for yourself will probably break, unless you're vendoring ferny
and running thorough regression tests on updates.

### "Wire format"

In general, unstructured data in the form of messages which `ssh` writes to its
stderr is collected.  In addition, "commands" can be received via structured
messages.

These commands are essentially asynchronous, one-directional remote procedure
calls.  There is no support for completion notification or return values
(although it's possible to add it at a higher level — see `ferny.askpass`,
below, for an example).

Each command has:
 - a command name (such as `ferny.askpass`)
 - zero or more arguments: values of any `repr()`-able type
 - zero or more file descriptors

Additionally, each command receives the unstructured stderr contents printed
before the command was sent.  This is useful for things like askpass
interactions which may want to present dialogs which also contain the previous
error messages (eg. "Permission denied, please try again.").

There are two ways to send commands, which are conceptually equivalent, but
only one of these methods supports passing file descriptors.

#### "Local" mechanism — can send file descriptors

These messages are always sent as a single nul ('\0') byte accompanied
by a number of file descriptors.  The first file descriptor is always the
reader end of a pipe from which the content of the command and arguments should
be read (until EOF).  It's a utf-8 string in the following form:

```python
    repr((command_name, tuple(args)))
```

The remaining file descriptors are the 'zero or more file descriptors' which
are part of the command being sent.

The "local" way of sending commands should be preferred whenever it is
available — even if sending a command without file descriptors.

#### "Remote" mechanism — can't send file descriptors

These messages are sent in the following form, as utf-8:

```python
    '\0ferny\0 + repr((command_name, tuple(args))) + '\0\0\n'
```

The command being sent has no possibility of receiving file descriptors if this
form is used, but this form can be sent in situations where stderr is (no
longer) a unix socket.  This might be useful for sending commands from remote
hosts over SSH, for example.

Note: with remote commands, extra care must be taken to ensure that the sender
of the command is the same version of ferny as running locally, and not a
version of ferny found on the remote host.  You should be using something like
`beiboot` for providing the program to the remote.

## Built-in commands

ferny contains a couple of commands implemented internally:

### `ferny.askpass`

This is the primary askpass interaction that occurs when the `ferny-askpass`
helper is invoked (usually by `ssh`, `sudo`, or similar).

The command expects to receive two arguments:
 - `sys.argv` of `ferny-askpass` as a tuple or list
 - `os.environ` of `ferny-askpass` as a dictionary

The command expects to receive two file descriptors:
 - the "status" file descriptor (see below)
 - the "stdout" file descriptor to which the answer will be written

Since the command receives file descriptors, it can only be sent using the
"local" mechanism described above.

The "status" file descriptor is a socket.  As long as it's open on both ends,
the interaction is considered to be running.  Either side can close it (or
half-close it) to signal that the interaction should end.

`ferny-askpass` will never write anything to it, so if it ever polls readable
then it means it's been closed.  This means that `ferny-askpass` has exited and
the interaction is over.  This can happen if `ferny-askpass` is killed (which
ssh sometimes does, for example).

When the interaction agent wishes to signal `ferny-askpass` to exit, it should
write an integer to the status socket and then close it.  This integer is used
as the exit status of `ferny-askpass`.  If no integer is passed, the exit
status is 1.

### `ferny.end`

This is command signals the interaction agent to exit.  It accepts no
parameters and no file descriptors.

## Custom commands

It's possible to implement your own commands.  If ferny receives a command that
it doesn't recognize, it will invoke the `.do_custom_command()` method on your
`InteractionResponder`.
