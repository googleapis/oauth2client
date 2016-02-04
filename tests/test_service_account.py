# Copyright 2014 Google Inc. All rights reserved.
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

"""Oauth2client tests.

Unit tests for service account credentials implemented using RSA.
"""

import datetime
import json
import os
import rsa
import unittest

import mock

from .http_mock import HttpMockSequence
from oauth2client.service_account import _ServiceAccountCredentials


def datafile(filename):
    # TODO(orestica): Refactor this using pkgutil.get_data
    f = open(os.path.join(os.path.dirname(__file__), 'data', filename), 'rb')
    data = f.read()
    f.close()
    return data


class ServiceAccountCredentialsTests(unittest.TestCase):

    def setUp(self):
        self.service_account_id = '123'
        self.service_account_email = 'dummy@google.com'
        self.private_key_id = 'ABCDEF'
        self.private_key = datafile('pem_from_pkcs12.pem')
        self.scopes = ['dummy_scope']
        self.credentials = _ServiceAccountCredentials(
            self.service_account_id,
            self.service_account_email,
            self.private_key_id,
            self.private_key,
            [])

    def test_sign_blob(self):
        private_key_id, signature = self.credentials.sign_blob('Google')
        self.assertEqual(self.private_key_id, private_key_id)

        pub_key = rsa.PublicKey.load_pkcs1_openssl_pem(
            datafile('publickey_openssl.pem'))

        self.assertTrue(rsa.pkcs1.verify(b'Google', signature, pub_key))

        self.assertRaises(rsa.pkcs1.VerificationError,
                          rsa.pkcs1.verify, b'Orest', signature, pub_key)
        self.assertRaises(rsa.pkcs1.VerificationError,
                          rsa.pkcs1.verify,
                          b'Google', b'bad signature', pub_key)

    def test_service_account_email(self):
        self.assertEqual(self.service_account_email,
                         self.credentials.service_account_email)

    def test_create_scoped_required_without_scopes(self):
        self.assertTrue(self.credentials.create_scoped_required())

    def test_create_scoped_required_with_scopes(self):
        self.credentials = _ServiceAccountCredentials(
            self.service_account_id,
            self.service_account_email,
            self.private_key_id,
            self.private_key,
            self.scopes)
        self.assertFalse(self.credentials.create_scoped_required())

    def test_create_scoped(self):
        new_credentials = self.credentials.create_scoped(self.scopes)
        self.assertNotEqual(self.credentials, new_credentials)
        self.assertTrue(isinstance(new_credentials,
                                   _ServiceAccountCredentials))
        self.assertEqual('dummy_scope', new_credentials._scopes)

    @mock.patch('oauth2client.client._UTCNOW')
    def test_access_token(self, utcnow):
        # Configure the patch.
        seconds = 11
        NOW = datetime.datetime(1992, 12, 31, second=seconds)
        utcnow.return_value = NOW

        # Create a custom credentials with a mock signer.
        signer = mock.MagicMock()
        signed_value = b'signed-content'
        signer.sign = mock.MagicMock(name='sign',
                                     return_value=signed_value)
        signer_patch = mock.patch('oauth2client.crypt.Signer.from_string',
                                  return_value=signer)
        with signer_patch as signer_factory:
            credentials = _ServiceAccountCredentials(
                self.service_account_id,
                self.service_account_email,
                self.private_key_id,
                self.private_key,
                '',
            )

        # Begin testing.
        lifetime = 2  # number of seconds in which the token expires
        EXPIRY_TIME = datetime.datetime(1992, 12, 31,
                                        second=seconds + lifetime)

        token1 = u'first_token'
        token_response_first = {
            'access_token': token1,
            'expires_in': lifetime,
        }
        token2 = u'second_token'
        token_response_second = {
            'access_token': token2,
            'expires_in': lifetime,
        }
        http = HttpMockSequence([
            ({'status': '200'},
             json.dumps(token_response_first).encode('utf-8')),
            ({'status': '200'},
             json.dumps(token_response_second).encode('utf-8')),
        ])

        # Get Access Token, First attempt.
        self.assertEqual(credentials.access_token, None)
        self.assertFalse(credentials.access_token_expired)
        self.assertEqual(credentials.token_expiry, None)
        token = credentials.get_access_token(http=http)
        self.assertEqual(credentials.token_expiry, EXPIRY_TIME)
        self.assertEqual(token1, token.access_token)
        self.assertEqual(lifetime, token.expires_in)
        self.assertEqual(token_response_first,
                         credentials.token_response)
        # Two utcnow calls are expected:
        # - get_access_token() -> _do_refresh_request (setting expires in)
        # - get_access_token() -> _expires_in()
        expected_utcnow_calls = [mock.call()] * 2
        self.assertEqual(expected_utcnow_calls, utcnow.mock_calls)
        # One call to sign() expected: Actual refresh was needed.
        self.assertEqual(len(signer.sign.mock_calls), 1)

        # Get Access Token, Second Attempt (not expired)
        self.assertEqual(credentials.access_token, token1)
        self.assertFalse(credentials.access_token_expired)
        token = credentials.get_access_token(http=http)
        # Make sure no refresh occurred since the token was not expired.
        self.assertEqual(token1, token.access_token)
        self.assertEqual(lifetime, token.expires_in)
        self.assertEqual(token_response_first, credentials.token_response)
        # Three more utcnow calls are expected:
        # - access_token_expired
        # - get_access_token() -> access_token_expired
        # - get_access_token -> _expires_in
        expected_utcnow_calls = [mock.call()] * (2 + 3)
        self.assertEqual(expected_utcnow_calls, utcnow.mock_calls)
        # No call to sign() expected: the token was not expired.
        self.assertEqual(len(signer.sign.mock_calls), 1 + 0)

        # Get Access Token, Third Attempt (force expiration)
        self.assertEqual(credentials.access_token, token1)
        credentials.token_expiry = NOW  # Manually force expiry.
        self.assertTrue(credentials.access_token_expired)
        token = credentials.get_access_token(http=http)
        # Make sure refresh occurred since the token was not expired.
        self.assertEqual(token2, token.access_token)
        self.assertEqual(lifetime, token.expires_in)
        self.assertFalse(credentials.access_token_expired)
        self.assertEqual(token_response_second,
                         credentials.token_response)
        # Five more utcnow calls are expected:
        # - access_token_expired
        # - get_access_token -> access_token_expired
        # - get_access_token -> _do_refresh_request
        # - get_access_token -> _expires_in
        # - access_token_expired
        expected_utcnow_calls = [mock.call()] * (2 + 3 + 5)
        self.assertEqual(expected_utcnow_calls, utcnow.mock_calls)
        # One more call to sign() expected: Actual refresh was needed.
        self.assertEqual(len(signer.sign.mock_calls), 1 + 0 + 1)

        self.assertEqual(credentials.access_token, token2)


if __name__ == '__main__':  # pragma: NO COVER
    unittest.main()
