#!/usr/bin/env python3

import docker
import unittest
import re
import time

# Regex patterns used for testing

# Checks if TLS 1.3 was negotiated
RE_PATTERN_HELLO_TLS_13_NORESUME = r"^.*Hello TLS 1.3 \(draft .*\) _o/$|^.*Hello TLS 1.3 _o/$"
# Checks if TLS 1.3 was resumed
RE_PATTERN_HELLO_TLS_13_RESUME   = r"Hello TLS 1.3 \[resumed\] _o/"
# Checks if 0-RTT was used and NOT confirmed
RE_PATTERN_HELLO_0RTT            = r"^.*Hello TLS 1.3 .*\[resumed\] \[0-RTT\] _o/$"
# Checks if 0-RTT was used and confirmed
RE_PATTERN_HELLO_0RTT_CONFIRMED  = r"^.*Hello TLS 1.3 .*\[resumed\] \[0-RTT confirmed\] _o/$"
# ALPN
RE_PATTERN_ALPN = "ALPN protocol: npn_proto$"
# Successful TLS establishement from TRIS
RE_TRIS_ALL_PASSED = ".*All handshakes passed.*"
# TLS handshake from BoringSSL with SIDH/P503-X25519
RE_BORINGSSL_P503 = "ECDHE curve: X25519-SIDHp503"

class Docker(object):
    ''' Utility class used for starting/stoping servers and clients during tests'''
    def __init__(self):
        self.d = docker.from_env()

    def close(self):
        self.d.close()

    def get_ip(self, server):
        tris_localserver_container = self.d.containers.get(server)
        return tris_localserver_container.attrs['NetworkSettings']['IPAddress']

    def run_client(self, image_name, cmd):
        ''' Runs client and returns tuple (status_code, logs) '''
        c = self.d.containers.run(image=image_name, detach=True, command=cmd)
        res = c.wait()
        ret = c.logs().decode('utf8')
        c.remove()
        return (res['StatusCode'], ret)

    def run_server(self, image_name, cmd=None, ports=None, entrypoint=None):
        ''' Starts server and returns docker container '''
        c = self.d.containers.run(image=image_name, auto_remove=True, detach=True, command=cmd, ports=ports, entrypoint=entrypoint)
        # TODO: maybe can be done better?
        time.sleep(3)
        return c

class RegexSelfTest(unittest.TestCase):
    ''' Ensures that those regexe's actually work '''

    LINE_HELLO_TLS      ="\nsomestuff\nHello TLS 1.3 _o/\nsomestuff"
    LINE_HELLO_DRAFT_TLS="\nsomestuff\nHello TLS 1.3 (draft 23) _o/\nsomestuff"

    LINE_HELLO_RESUMED  ="\nsomestuff\nHello TLS 1.3 [resumed] _o/\nsomestuff"
    LINE_HELLO_MIXED    ="\nsomestuff\nHello TLS 1.3 (draft 23) _o/\nHello TLS 1.3 (draft 23) [resumed] _o/\nsomestuff"
    LINE_HELLO_TLS_12   ="\nsomestuff\nHello TLS 1.2 (draft 23) [resumed] _o/\nsomestuff"
    LINE_HELLO_TLS_13_0RTT="\nsomestuff\nHello TLS 1.3 (draft 23) [resumed] [0-RTT] _o/\nsomestuff"
    LINE_HELLO_TLS_13_0RTT_CONFIRMED="\nsomestuff\nHello TLS 1.3 (draft 23) [resumed] [0-RTT confirmed] _o/\nsomestuff"
    def test_regexes(self):
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_TLS_13_NORESUME, RegexSelfTest.LINE_HELLO_TLS, re.MULTILINE))
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_TLS_13_NORESUME, RegexSelfTest.LINE_HELLO_DRAFT_TLS, re.MULTILINE))
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_TLS_13_RESUME, RegexSelfTest.LINE_HELLO_RESUMED, re.MULTILINE))
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_0RTT, RegexSelfTest.LINE_HELLO_TLS_13_0RTT, re.MULTILINE))
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_0RTT_CONFIRMED, RegexSelfTest.LINE_HELLO_TLS_13_0RTT_CONFIRMED, re.MULTILINE))

        # negative cases

        # expects 1.3, but 1.2 received
        self.assertIsNone(
            re.search(RE_PATTERN_HELLO_TLS_13_NORESUME, RegexSelfTest.LINE_HELLO_TLS_12, re.MULTILINE))
        # expects 0-RTT
        self.assertIsNone(
            re.search(RE_PATTERN_HELLO_TLS_13_RESUME, RegexSelfTest.LINE_HELLO_TLS_13_0RTT, re.MULTILINE))
        # expectes 0-RTT confirmed
        self.assertIsNone(
            re.search(RE_PATTERN_HELLO_0RTT, RegexSelfTest.LINE_HELLO_TLS_13_0RTT_CONFIRMED, re.MULTILINE))
        # expects resume without 0-RTT
        self.assertIsNone(
            re.search(RE_PATTERN_HELLO_TLS_13_RESUME, RegexSelfTest.LINE_HELLO_TLS_13_0RTT, re.MULTILINE))


class InteropServer(object):
    ''' Instantiates TRIS as a server '''

    TRIS_SERVER_NAME = "tris-localserver"

    @classmethod
    def setUpClass(self):
        self.d = Docker()
        try:
            self.server = self.d.run_server(self.TRIS_SERVER_NAME)
        except:
            self.d.close()
            raise

    @classmethod
    def tearDownClass(self):
        self.server.kill()
        self.d.close()

    @property
    def server_ip(self):
        return self.d.get_ip(self.server.name)

# Mixins for testing server functionality

class ServerNominalMixin(object):
    ''' Nominal tests for TLS 1.3 - client tries to perform handshake with server '''
    def test_rsa(self):
        res = self.d.run_client(self.CLIENT_NAME, self.server_ip+":"+'1443')
        self.assertTrue(res[0] == 0)
        # Check there was TLS hello without resume
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_TLS_13_NORESUME, res[1], re.MULTILINE))
        # Check there was TLS hello with resume
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_TLS_13_RESUME, res[1], re.MULTILINE))

    def test_ecdsa(self):
        res = self.d.run_client(self.CLIENT_NAME, self.server_ip+":"+'2443')
        self.assertTrue(res[0] == 0)
        # Check there was TLS hello without resume
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_TLS_13_NORESUME, res[1], re.MULTILINE))
        # Check there was TLS hello with resume
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_TLS_13_RESUME, res[1], re.MULTILINE))

class ServerClientAuthMixin(object):
    ''' Client authentication testing '''
    def test_client_auth(self):
        args = ''.join([self.server_ip+':6443',' -key client_rsa.key -cert client_rsa.crt -debug'])
        res = self.d.run_client(self.CLIENT_NAME, args)
        self.assertEqual(res[0], 0)
        # Check there was TLS hello without resume
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_TLS_13_NORESUME, res[1], re.MULTILINE))
        # Check there was TLS hello with resume
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_TLS_13_RESUME, res[1], re.MULTILINE))

class ClientNominalMixin(object):

    def test_rsa(self):
        res = self.d.run_client(self.CLIENT_NAME, '-ecdsa=false '+self.server_ip+":1443")
        self.assertEqual(res[0], 0)

    def test_ecdsa(self):
        res = self.d.run_client(self.CLIENT_NAME, '-rsa=false '+self.server_ip+":2443")
        self.assertEqual(res[0], 0)


class ClientClientAuthMixin(object):
    ''' Client authentication testing - tris on client side '''

    def test_client_auth(self):
        res = self.d.run_client('tris-testclient', '-rsa=false -cliauth '+self.server_ip+":6443")
        self.assertTrue(res[0] == 0)

class ServerZeroRttMixin(object):
    ''' Zero RTT testing '''

    def test_zero_rtt(self):
        # rejecting 0-RTT
        res = self.d.run_client(self.CLIENT_NAME, self.server_ip+":3443")
        self.assertEqual(res[0], 0)
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_TLS_13_RESUME, res[1], re.MULTILINE))
        self.assertIsNone(
            re.search(RE_PATTERN_HELLO_0RTT, res[1], re.MULTILINE))

        # accepting 0-RTT
        res = self.d.run_client(self.CLIENT_NAME, self.server_ip+":4443")
        self.assertEqual(res[0], 0)
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_0RTT, res[1], re.MULTILINE))

        # confirming 0-RTT
        res = self.d.run_client(self.CLIENT_NAME, self.server_ip+":5443")
        self.assertEqual(res[0], 0)
        self.assertIsNotNone(
            re.search(RE_PATTERN_HELLO_0RTT_CONFIRMED, res[1], re.MULTILINE))

class InteropClient(object):
    ''' Instantiates TRIS as a client '''

    CLIENT_NAME = "tris-testclient"

    @classmethod
    def setUpClass(self):
        self.d = Docker()
        try:
            self.server = self.d.run_server(
                                self.SERVER_NAME,
                                ports={ '1443/tcp': None, '2443/tcp': None, '6443/tcp': None, '7443/tcp': None},
                                entrypoint="/server.sh")
        except:
            self.d.close()
            raise

    @classmethod
    def tearDownClass(self):
        self.server.kill()
        self.d.close()

    @property
    def server_ip(self):
        return self.d.get_ip(self.server.name)

# Actual test definition

# TRIS as a server, BoringSSL as a client
class InteropServer_BoringSSL(InteropServer, ServerNominalMixin, ServerClientAuthMixin, unittest.TestCase):

    CLIENT_NAME = "tls-tris:boring"

    def test_ALPN(self):
        '''
        Checks wether ALPN is sent back by tris server in EncryptedExtensions in case of TLS 1.3. The
        ALPN protocol is set to 'npn_proto', which is hardcoded in TRIS test server.
        '''
        res = self.d.run_client(self.CLIENT_NAME, self.server_ip+":1443 "+'-alpn-protos npn_proto')
        self.assertEqual(res[0], 0)
        self.assertIsNotNone(re.search(RE_PATTERN_ALPN, res[1], re.MULTILINE))

    def test_SIDH(self):
        '''
        Connects to TRIS server listening on 7443 and tries to perform key agreement with SIDH/P503-X25519
        '''
        res = self.d.run_client(self.CLIENT_NAME, self.server_ip+":7443 "+'-curves X25519-SIDHp503')
        self.assertEqual(res[0], 0)
        self.assertIsNotNone(re.search(RE_BORINGSSL_P503, res[1], re.MULTILINE))
        self.assertIsNotNone(re.search(RE_PATTERN_HELLO_TLS_13_NORESUME, res[1], re.MULTILINE))

# PicoTLS doesn't seem to implement draft-23 correctly. It will
# be enabled when draft-28 is implemented.
# class InteropServer_PicoTLS(
#         InteropServer,
#         ServerNominalMixin,
#         ServerZeroRttMixin,
#         unittest.TestCase
#     ): CLIENT_NAME = "tls-tris:picotls"

class InteropServer_NSS(
        InteropServer,
        ServerNominalMixin,
        ServerZeroRttMixin,
        unittest.TestCase
    ): CLIENT_NAME = "tls-tris:tstclnt"

# TRIS as a client, BoringSSL as a server
class InteropClient_BoringSSL(InteropClient, ClientNominalMixin, ClientClientAuthMixin, unittest.TestCase):

    SERVER_NAME = "boring-localserver"

    def test_SIDH(self):
        '''
        Connects to BoringSSL server listening on 7443 and tries to perform key agreement with SIDH/P503-X25519
        '''
        res = self.d.run_client(self.CLIENT_NAME, '-rsa=false -ecdsa=true -groups X25519-SIDHp503 ' + self.server_ip+":7443")
        self.assertEqual(res[0], 0)
        self.assertIsNotNone(re.search(RE_TRIS_ALL_PASSED, res[1], re.MULTILINE))

    def test_SIDH_TLSv12(self):
        '''
        Connects to TRIS server listening on 7443 and tries to perform key agreement with SIDH/P503-X25519
        This connection will be over TLSv12 and hence it should fall back to X25519
        '''
        res = self.d.run_client(self.CLIENT_NAME, '-tls_version=1.2 -rsa=false -ecdsa=true -groups X25519-SIDHp503:P-256 -ciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ' + self.server_ip+":7443")
        self.assertEqual(res[0], 0)
        # Go doesn't provide API to get NamedGroup ID, but boringssl on port 7443 accepts only TLS1.2
        # so if handshake was successful, then that's all what we need
        self.assertIsNotNone(re.search(RE_TRIS_ALL_PASSED, res[1], re.MULTILINE))

class InteropClient_NSS(
        InteropClient,
        ClientNominalMixin,
        unittest.TestCase
    ): SERVER_NAME = "tstclnt-localserver"

# TRIS as a client
class InteropServer_TRIS(ClientNominalMixin, InteropServer, unittest.TestCase):

    CLIENT_NAME = 'tris-testclient'

    def test_client_auth(self):
        # I need to block TLS v1.2 as test server needs some rework
        res = self.d.run_client(self.CLIENT_NAME, '-rsa=false -ecdsa=false -cliauth '+self.server_ip+":6443")
        self.assertEqual(res[0], 0)

    def test_SIDH(self):
        res = self.d.run_client(self.CLIENT_NAME, '-rsa=false -ecdsa=true -groups X25519-SIDHp503 '+self.server_ip+":7443")
        self.assertEqual(res[0], 0)

    def test_SIKE(self):
        res = self.d.run_client(self.CLIENT_NAME, '-rsa=false -ecdsa=true -groups X25519-SIKEp503 '+self.server_ip+":7443")
        self.assertEqual(res[0], 0)

    def test_server_doesnt_support_SIDH(self):
        '''
        Client advertises HybridSIDH and ECDH. Server supports ECDH only. Checks weather
        TLS session can still be established.
        '''
        res = self.d.run_client(self.CLIENT_NAME, '-rsa=false -ecdsa=true '+self.server_ip+":7443")
        self.assertEqual(res[0], 0)

if __name__ == '__main__':
    unittest.main()
