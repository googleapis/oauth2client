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

"""Tests for oauth2client.gce.

Unit tests for oauth2client.gce.
"""

__author__ = 'jcgregorio@google.com (Joe Gregorio)'

import json
from six.moves import urllib
import unittest

import httplib2
import mock

from oauth2client._helpers import _to_bytes
from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import Credentials
from oauth2client.client import save_to_well_known_file
from oauth2client.gce import AppAssertionCredentials


class AssertionCredentialsTests(unittest.TestCase):

    def _refresh_success_helper(self, bytes_response=False):
        access_token = u'this-is-a-token'
        return_val = json.dumps({u'accessToken': access_token})
        if bytes_response:
            return_val = _to_bytes(return_val)
        http = mock.MagicMock()
        http.request = mock.MagicMock(
        return_value=(mock.Mock(status=200), return_val))

        scopes = ['http://example.com/a', 'http://example.com/b']
        credentials = AppAssertionCredentials(scope=scopes)
        self.assertEquals(None, credentials.access_token)
        credentials.refresh(http)
        self.assertEquals(access_token, credentials.access_token)

        base_metadata_uri = ('http://metadata.google.internal/0.1/meta-data/'
                         'service-accounts/default/acquire')
        escaped_scopes = urllib.parse.quote(' '.join(scopes), safe='')
        request_uri = base_metadata_uri + '?scope=' + escaped_scopes
        http.request.assert_called_once_with(request_uri)

    def test_refresh_success(self):
        self._refresh_success_helper(bytes_response=False)

    def test_refresh_success_bytes(self):
        self._refresh_success_helper(bytes_response=True)

    def test_fail_refresh(self):
        http = mock.MagicMock()
        http.request = mock.MagicMock(return_value=(mock.Mock(status=400), '{}'))

        c = AppAssertionCredentials(scope=['http://example.com/a',
                                       'http://example.com/b'])
        self.assertRaises(AccessTokenRefreshError, c.refresh, http)

    def test_to_from_json(self):
        c = AppAssertionCredentials(scope=['http://example.com/a',
                                       'http://example.com/b'])
        json = c.to_json()
        c2 = Credentials.new_from_json(json)

        self.assertEqual(c.access_token, c2.access_token)

    def test_create_scoped_required_without_scopes(self):
        credentials = AppAssertionCredentials([])
        self.assertTrue(credentials.create_scoped_required())

    def test_create_scoped_required_with_scopes(self):
        credentials = AppAssertionCredentials(['dummy_scope'])
        self.assertFalse(credentials.create_scoped_required())

    def test_create_scoped(self):
        credentials = AppAssertionCredentials([])
        new_credentials = credentials.create_scoped(['dummy_scope'])
        self.assertNotEqual(credentials, new_credentials)
        self.assertTrue(isinstance(new_credentials, AppAssertionCredentials))
        self.assertEqual('dummy_scope', new_credentials.scope)

    def test_get_access_token(self):
        http = mock.MagicMock()
        http.request = mock.MagicMock(
        return_value=(mock.Mock(status=200),
                      '{"accessToken": "this-is-a-token"}'))

        credentials = AppAssertionCredentials(['dummy_scope'])
        token = credentials.get_access_token(http=http)
        self.assertEqual('this-is-a-token', token.access_token)
        self.assertEqual(None, token.expires_in)

        http.request.assert_called_once_with(
        'http://metadata.google.internal/0.1/meta-data/service-accounts/'
        'default/acquire?scope=dummy_scope')

    def test_save_to_well_known_file(self):
        import os
        ORIGINAL_ISDIR = os.path.isdir
        try:
            os.path.isdir = lambda path: True
            credentials = AppAssertionCredentials([])
            self.assertRaises(NotImplementedError, save_to_well_known_file,
                        credentials)
        finally:
            os.path.isdir = ORIGINAL_ISDIR
