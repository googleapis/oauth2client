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

import httplib2
try:
  from mox3 import mox
except ImportError:
  import mox
import unittest

from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import Credentials
from oauth2client.client import save_to_well_known_file
from oauth2client.gce import AppAssertionCredentials


class AssertionCredentialsTests(unittest.TestCase):

  def test_good_refresh(self):
    m = mox.Mox()

    httplib2_response = m.CreateMock(object)
    httplib2_response.status = 200

    httplib2_request = m.CreateMock(object)
    httplib2_request.__call__(
        ('http://metadata.google.internal/0.1/meta-data/service-accounts/'
         'default/acquire'
         '?scope=http%3A%2F%2Fexample.com%2Fa%20http%3A%2F%2Fexample.com%2Fb'
        )).AndReturn((httplib2_response, '{"accessToken": "this-is-a-token"}'))

    m.ReplayAll()

    c = AppAssertionCredentials(scope=['http://example.com/a',
                                       'http://example.com/b'])

    c._refresh(httplib2_request)

    self.assertEquals('this-is-a-token', c.access_token)

    m.UnsetStubs()
    m.VerifyAll()

  def test_fail_refresh(self):
    m = mox.Mox()

    httplib2_response = m.CreateMock(object)
    httplib2_response.status = 400

    httplib2_request = m.CreateMock(object)
    httplib2_request.__call__(
        ('http://metadata.google.internal/0.1/meta-data/service-accounts/'
         'default/acquire'
         '?scope=http%3A%2F%2Fexample.com%2Fa%20http%3A%2F%2Fexample.com%2Fb'
        )).AndReturn((httplib2_response, '{"accessToken": "this-is-a-token"}'))

    m.ReplayAll()

    c = AppAssertionCredentials(scope=['http://example.com/a',
                                       'http://example.com/b'])

    try:
      c._refresh(httplib2_request)
      self.fail('Should have raised exception on 400')
    except AccessTokenRefreshError:
      pass

    m.UnsetStubs()
    m.VerifyAll()

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
    m = mox.Mox()

    httplib2_response = m.CreateMock(object)
    httplib2_response.status = 200

    httplib2_request = m.CreateMock(object)
    httplib2_request.__call__(
        ('http://metadata.google.internal/0.1/meta-data/service-accounts/'
         'default/acquire?scope=dummy_scope'
        )).AndReturn((httplib2_response, '{"accessToken": "this-is-a-token"}'))

    m.ReplayAll()

    credentials = AppAssertionCredentials(['dummy_scope'])

    http = httplib2.Http()
    http.request = httplib2_request

    token = credentials.get_access_token(http=http)
    self.assertEqual('this-is-a-token', token.access_token)
    self.assertEqual(None, token.expires_in)

    m.UnsetStubs()
    m.VerifyAll()

  def test_save_to_well_known_file(self):
    credentials = AppAssertionCredentials([])
    self.assertRaises(NotImplementedError, save_to_well_known_file, credentials)
