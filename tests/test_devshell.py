# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for oauth2client.devshell."""

import json
import os
import socket
import threading
import unittest

import mock

from oauth2client._helpers import _to_bytes
from oauth2client.client import save_to_well_known_file
from oauth2client.devshell import _SendRecv
from oauth2client.devshell import CREDENTIAL_INFO_REQUEST_JSON
from oauth2client.devshell import CommunicationError
from oauth2client.devshell import CredentialInfoResponse
from oauth2client.devshell import DEVSHELL_ENV
from oauth2client.devshell import DevshellCredentials
from oauth2client.devshell import NoDevshellServer


class TestCredentialInfoResponse(unittest.TestCase):

    def test_constructor_with_non_list(self):
        json_non_list = '{}'
        self.assertRaises(ValueError, CredentialInfoResponse,
                          json_non_list)

    def test_constructor_with_bad_json(self):
        json_non_list = '{BADJSON'
        self.assertRaises(ValueError, CredentialInfoResponse,
                          json_non_list)

    def test_constructor_empty_list(self):
        info_response = CredentialInfoResponse('[]')
        self.assertEqual(info_response.user_email, None)
        self.assertEqual(info_response.project_id, None)
        self.assertEqual(info_response.access_token, None)

    def test_constructor_full_list(self):
        user_email = 'user_email'
        project_id = 'project_id'
        access_token = 'access_token'
        json_string = json.dumps([user_email, project_id, access_token])
        info_response = CredentialInfoResponse(json_string)
        self.assertEqual(info_response.user_email, user_email)
        self.assertEqual(info_response.project_id, project_id)
        self.assertEqual(info_response.access_token, access_token)


class Test_SendRecv(unittest.TestCase):

    def test_port_zero(self):
        with mock.patch('oauth2client.devshell.os') as os_mod:
            os_mod.getenv = mock.MagicMock(name='getenv', return_value=0)
            self.assertRaises(NoDevshellServer, _SendRecv)
            os_mod.getenv.assert_called_once_with(DEVSHELL_ENV, 0)

    def test_no_newline_in_received_header(self):
        non_zero_port = 1
        sock = mock.MagicMock()

        header_without_newline = ''
        sock.recv(6).decode = mock.MagicMock(
            name='decode', return_value=header_without_newline)

        with mock.patch('oauth2client.devshell.os') as os_mod:
            os_mod.getenv = mock.MagicMock(name='getenv',
                                           return_value=non_zero_port)
            with mock.patch('oauth2client.devshell.socket') as socket:
                socket.socket = mock.MagicMock(name='socket',
                                               return_value=sock)
                self.assertRaises(CommunicationError, _SendRecv)
                os_mod.getenv.assert_called_once_with(DEVSHELL_ENV, 0)
                socket.socket.assert_called_once_with()
                sock.recv(6).decode.assert_called_once_with()

                data = CREDENTIAL_INFO_REQUEST_JSON
                msg = _to_bytes('%s\n%s' % (len(data), data), encoding='utf-8')
                expected_sock_calls = [
                    mock.call.recv(6),  # From the set-up above
                    mock.call.connect(('localhost', non_zero_port)),
                    mock.call.sendall(msg),
                    mock.call.recv(6),
                    mock.call.recv(6),  # From the check above
                ]
                self.assertEqual(sock.method_calls, expected_sock_calls)


class _AuthReferenceServer(threading.Thread):

    def __init__(self, response=None):
        super(_AuthReferenceServer, self).__init__(None)
        self.response = (response or
                         '["joe@example.com", "fooproj", "sometoken"]')

    def __enter__(self):
        self.start_server()

    def start_server(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind(('localhost', 0))
        port = self._socket.getsockname()[1]
        os.environ[DEVSHELL_ENV] = str(port)
        self._socket.listen(0)
        self.daemon = True
        self.start()
        return self

    def __exit__(self, e_type, value, traceback):
        self.stop_server()

    def stop_server(self):
        del os.environ[DEVSHELL_ENV]
        self._socket.close()

    def run(self):
        s = None
        try:
            # Do not set the timeout on the socket, leave it in the blocking
            # mode as setting the timeout seems to cause spurious EAGAIN
            # errors on OSX.
            self._socket.settimeout(None)

            s, unused_addr = self._socket.accept()
            resp_buffer = ''
            resp_1 = s.recv(6).decode()
            if '\n' not in resp_1:
                raise Exception('invalid request data')
            nstr, extra = resp_1.split('\n', 1)
            resp_buffer = extra
            n = int(nstr)
            to_read = n - len(extra)
            if to_read > 0:
                resp_buffer += s.recv(to_read, socket.MSG_WAITALL)
            if resp_buffer != CREDENTIAL_INFO_REQUEST_JSON:
                raise Exception('bad request')
            l = len(self.response)
            s.sendall(('%d\n%s' % (l, self.response)).encode())
        finally:
            if s:
                s.close()


class DevshellCredentialsTests(unittest.TestCase):

    def test_signals_no_server(self):
        self.assertRaises(NoDevshellServer, DevshellCredentials)

    def test_request_response(self):
        with _AuthReferenceServer():
            response = _SendRecv()
            self.assertEqual(response.user_email, 'joe@example.com')
            self.assertEqual(response.project_id, 'fooproj')
            self.assertEqual(response.access_token, 'sometoken')

    def test_no_refresh_token(self):
        with _AuthReferenceServer():
            creds = DevshellCredentials()
            self.assertEquals(None, creds.refresh_token)

    def test_reads_credentials(self):
        with _AuthReferenceServer():
            creds = DevshellCredentials()
            self.assertEqual('joe@example.com', creds.user_email)
            self.assertEqual('fooproj', creds.project_id)
            self.assertEqual('sometoken', creds.access_token)

    def test_handles_skipped_fields(self):
        with _AuthReferenceServer('["joe@example.com"]'):
            creds = DevshellCredentials()
            self.assertEqual('joe@example.com', creds.user_email)
            self.assertEqual(None, creds.project_id)
            self.assertEqual(None, creds.access_token)

    def test_handles_tiny_response(self):
        with _AuthReferenceServer('[]'):
            creds = DevshellCredentials()
            self.assertEqual(None, creds.user_email)
            self.assertEqual(None, creds.project_id)
            self.assertEqual(None, creds.access_token)

    def test_handles_ignores_extra_fields(self):
        with _AuthReferenceServer(
                '["joe@example.com", "fooproj", "sometoken", "extra"]'):
            creds = DevshellCredentials()
            self.assertEqual('joe@example.com', creds.user_email)
            self.assertEqual('fooproj', creds.project_id)
            self.assertEqual('sometoken', creds.access_token)

    def test_refuses_to_save_to_well_known_file(self):
        ORIGINAL_ISDIR = os.path.isdir
        try:
            os.path.isdir = lambda path: True
            with _AuthReferenceServer():
                creds = DevshellCredentials()
                self.assertRaises(NotImplementedError,
                                  save_to_well_known_file, creds)
        finally:
            os.path.isdir = ORIGINAL_ISDIR

    def test_from_json(self):
        self.assertRaises(NotImplementedError,
                          DevshellCredentials.from_json, None)

    def test_serialization_data(self):
        with _AuthReferenceServer('[]'):
            credentials = DevshellCredentials()
            self.assertRaises(NotImplementedError, getattr,
                              credentials, 'serialization_data')
