# ferny

ferny is a Python API wrapped around `ssh(1)`.

This project was undertaken as a replacement for our libssh-based SSH support
in [Cockpit](https://github.com/cockpit-project/cockpit).

The main motivation is to stop playing catch-up with the configuration options
and algorithm support in OpenSSH by simply using OpenSSH directly.

The API is `async`/`await` oriented, based on Python standard `asyncio`.

Take a look at the `examples/` directory to get a feel for the API.
