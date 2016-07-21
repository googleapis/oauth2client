# Copyright 2016 Google Inc. All rights reserved.
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

import datetime
import json

import httplib2
import mock
from six.moves import http_client
import unittest2

from oauth2client.contrib import _metadata

PATH = 'instance/service-accounts/default'
DATA = {'foo': 'bar'}
EXPECTED_URL = (
    'http://metadata.google.internal/computeMetadata/v1/instance'
    '/service-accounts/default')
EXPECTED_KWARGS = dict(headers=_metadata.METADATA_HEADERS)


def request_mock(status, content_type, content):
    return mock.MagicMock(return_value=(
        httplib2.Response(
            {'status': status, 'content-type': content_type}
        ),
        content.encode('utf-8')
    ))


class TestMetadata(unittest2.TestCase):

    def test_get_success_json(self):
        http_request = request_mock(
            http_client.OK, 'application/json', json.dumps(DATA))
        self.assertEqual(
            _metadata.get(http_request, PATH),
            DATA
        )
        http_request.assert_called_once_with(EXPECTED_URL, **EXPECTED_KWARGS)

    def test_get_success_string(self):
        http_request = request_mock(
            http_client.OK, 'text/html', '<p>Hello World!</p>')
        self.assertEqual(
            _metadata.get(http_request, PATH),
            '<p>Hello World!</p>'
        )
        http_request.assert_called_once_with(EXPECTED_URL, **EXPECTED_KWARGS)

    def test_get_failure(self):
        http_request = request_mock(
            http_client.NOT_FOUND, 'text/html', '<p>Error</p>')
        with self.assertRaises(httplib2.HttpLib2Error):
            _metadata.get(http_request, PATH)

        http_request.assert_called_once_with(EXPECTED_URL, **EXPECTED_KWARGS)

    @mock.patch(
        'oauth2client.client._UTCNOW',
        return_value=datetime.datetime.min)
    def test_get_token_success(self, now):
        http_request = request_mock(
            http_client.OK,
            'application/json',
            json.dumps({'access_token': 'a', 'expires_in': 100})
        )
        token, expiry = _metadata.get_token(http_request=http_request)
        self.assertEqual(token, 'a')
        self.assertEqual(
            expiry, datetime.datetime.min + datetime.timedelta(seconds=100))
        http_request.assert_called_once_with(
            EXPECTED_URL + '/token',
            **EXPECTED_KWARGS
        )
        now.assert_called_once_with()

    def test_service_account_info(self):
        http_request = request_mock(
            http_client.OK, 'application/json', json.dumps(DATA))
        info = _metadata.get_service_account_info(http_request)
        self.assertEqual(info, DATA)
        http_request.assert_called_once_with(
            EXPECTED_URL + '/?recursive=True',
            **EXPECTED_KWARGS
        )
