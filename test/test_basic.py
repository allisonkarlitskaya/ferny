import os
import unittest

import mockssh

import ferny

os.environ.pop('SSH_AUTH_SOCK', None)
os.environ.pop('SSH_ASKPASS', None)


class MockAskpass(ferny.Askpass):
    async def askpass(self, msg, hint):
        if 'fingerprint' in msg:
            return 'yes'
        else:
            return 'passphrase'


class TestBasic(unittest.IsolatedAsyncioTestCase):
    async def test_rsa_key(self):
        users = {'admin': 'test/id_rsa'}
        with mockssh.Server(users) as server:
            session = ferny.Session()
            await session.connect(server.host,
                                  port=server.port,
                                  configfile='none',
                                  options={'UserKnownHostsFile': '/dev/null'},
                                  identity_file='test/id_rsa.enc',
                                  login_name='admin',
                                  askpass_factory=MockAskpass)
            print('done!')
            await session.disconnect()
