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

"""Unit tests for oauth2client.contrib.gce."""

import datetime
import json

import mock
from six.moves import http_client
from six.moves import urllib
import unittest2

from oauth2client.client import Credentials
from oauth2client.client import save_to_well_known_file
from oauth2client.client import HttpAccessTokenRefreshError
from oauth2client.contrib.gce import _SCOPES_WARNING
from oauth2client.contrib.gce import AppAssertionCredentials
from tests.contrib.test_metadata import request_mock

__author__ = 'jcgregorio@google.com (Joe Gregorio)'


class AppAssertionCredentialsTests(unittest2.TestCase):

    def test_constructor(self):
        credentials = AppAssertionCredentials(foo='bar')
        self.assertEqual(credentials.scope, '')
        self.assertEqual(credentials.kwargs, {'foo': 'bar'})
        self.assertEqual(credentials.assertion_type, None)

    @mock.patch('warnings.warn')
    def test_constructor_with_scopes(self, warn_mock):
        scope = 'http://example.com/a http://example.com/b'
        scopes = scope.split()
        credentials = AppAssertionCredentials(scope=scopes, foo='bar')
        self.assertEqual(credentials.scope, scope)
        self.assertEqual(credentials.kwargs, {'foo': 'bar'})
        self.assertEqual(credentials.assertion_type, None)
        warn_mock.assert_called_once_with(_SCOPES_WARNING)

    def test_to_json_and_from_json(self):
        credentials = AppAssertionCredentials()
        json = credentials.to_json()
        credentials_from_json = Credentials.new_from_json(json)
        self.assertEqual(credentials.access_token,
                         credentials_from_json.access_token)

    @mock.patch('oauth2client.contrib._metadata.get_token',
                side_effect=[('A', datetime.datetime.min),
                             ('B', datetime.datetime.max)])
    def test_refresh_token(self, metadata):
        credentials = AppAssertionCredentials()
        self.assertIsNone(credentials.access_token)
        credentials.get_access_token()
        self.assertEqual(credentials.access_token, 'A')
        self.assertTrue(credentials.access_token_expired)
        credentials.get_access_token()
        self.assertEqual(credentials.access_token, 'B')
        self.assertFalse(credentials.access_token_expired)

    def test_refresh_token_failed_fetch(self):
        http_request = request_mock(
            http_client.NOT_FOUND,
            'application/json',
            json.dumps({'access_token': 'a', 'expires_in': 100})
        )
        credentials = AppAssertionCredentials()

        with self.assertRaises(HttpAccessTokenRefreshError):
            credentials._refresh(http_request=http_request)

    def test_serialization_data(self):
        credentials = AppAssertionCredentials()
        self.assertRaises(NotImplementedError, getattr,
                          credentials, 'serialization_data')

    def test_create_scoped_required_without_scopes(self):
        credentials = AppAssertionCredentials()
        self.assertFalse(credentials.create_scoped_required())

    @mock.patch('warnings.warn')
    def test_create_scoped_required_with_scopes(self, warn_mock):
        credentials = AppAssertionCredentials(['dummy_scope'])
        self.assertFalse(credentials.create_scoped_required())
        warn_mock.assert_called_once_with(_SCOPES_WARNING)

    @mock.patch('warnings.warn')
    def test_create_scoped(self, warn_mock):
        credentials = AppAssertionCredentials()
        new_credentials = credentials.create_scoped(['dummy_scope'])
        self.assertNotEqual(credentials, new_credentials)
        self.assertTrue(isinstance(new_credentials, AppAssertionCredentials))
        self.assertEqual('dummy_scope', new_credentials.scope)
        warn_mock.assert_called_once_with(_SCOPES_WARNING)

    def test_sign_blob_not_implemented(self):
        credentials = AppAssertionCredentials([])
        with self.assertRaises(NotImplementedError):
            credentials.sign_blob(b'blob')

    @mock.patch('oauth2client.contrib._metadata.get_service_account_info',
                return_value={'email': 'a@example.com'})
    def test_service_account_email(self, metadata):
        credentials = AppAssertionCredentials()
        # Assert that service account isn't pre-fetched
        metadata.assert_not_called()
        self.assertEqual(credentials.service_account_email, 'a@example.com')

    def test_save_to_well_known_file(self):
        import os
        ORIGINAL_ISDIR = os.path.isdir
        try:
            os.path.isdir = lambda path: True
            credentials = AppAssertionCredentials()
            self.assertRaises(NotImplementedError, save_to_well_known_file,
                              credentials)
        finally:
            os.path.isdir = ORIGINAL_ISDIR


if __name__ == '__main__':  # pragma: NO COVER
    unittest2.main()
