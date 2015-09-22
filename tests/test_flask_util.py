# Copyright 2015 Google Inc. All rights reserved.
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

"""Unit tests for the Flask utilities"""

import httplib2
import json
import unittest

import flask
import six.moves.http_client as httplib
import mock
import six.moves.urllib.parse as urlparse

from oauth2client import GOOGLE_AUTH_URI
from oauth2client import GOOGLE_TOKEN_URI
from oauth2client import clientsecrets
from oauth2client.flask_util import UserOAuth2 as FlaskOAuth2
from oauth2client.client import OAuth2Credentials


__author__ = 'jonwayne@google.com (Jon Wayne Parrott)'


class Http2Mock(object):
    """Mock httplib2.Http for code exchange / refresh"""

    def __init__(self, status=httplib.OK, **kwargs):
        self.status = status
        self.content = {
            'access_token': 'foo_access_token',
            'refresh_token': 'foo_refresh_token',
            'expires_in': 3600,
            'extra': 'value',
        }
        self.content.update(kwargs)

    def request(self, token_uri, method, body, headers, *args, **kwargs):
        self.body = body
        self.headers = headers
        return (self, json.dumps(self.content).encode('utf-8'))

    def __enter__(self):
        self.httplib2_orig = httplib2.Http
        httplib2.Http = self
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        httplib2.Http = self.httplib2_orig

    def __call__(self, *args, **kwargs):
        return self


class FlaskOAuth2Tests(unittest.TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.testing = True
        self.app.config['SECRET_KEY'] = 'notasecert'
        self.oauth2 = FlaskOAuth2(
            self.app,
            client_id='client_idz',
            client_secret='client_secretz')

    def _generate_credentials(self, scopes=None):
        return OAuth2Credentials(
            'access_tokenz',
            'client_idz',
            'client_secretz',
            'refresh_tokenz',
            '3600',
            GOOGLE_TOKEN_URI,
            'Test',
            id_token={
                'sub': '123',
                'email': 'user@example.com'
            },
            scopes=scopes)

    def test_explicit_configuration(self):
        oauth2 = FlaskOAuth2(
            flask.Flask(__name__), client_id='id', client_secret='secret')

        self.assertEqual(oauth2.client_id, 'id')
        self.assertEqual(oauth2.client_secret, 'secret')

        return_val = (
            clientsecrets.TYPE_WEB,
            {'client_id': 'id', 'client_secret': 'secret'})

        with mock.patch('oauth2client.clientsecrets.loadfile',
                        return_value=return_val):

            oauth2 = FlaskOAuth2(
                flask.Flask(__name__), client_secrets_file='file.json')

            self.assertEqual(oauth2.client_id, 'id')
            self.assertEqual(oauth2.client_secret, 'secret')

    def test_delayed_configuration(self):
        app = flask.Flask(__name__)
        oauth2 = FlaskOAuth2()
        oauth2.init_app(app, client_id='id', client_secret='secret')
        self.assertEqual(oauth2.app, app)

    def test_explicit_storage(self):
        storage_mock = mock.Mock()
        oauth2 = FlaskOAuth2(
            flask.Flask(__name__), storage=storage_mock, client_id='id',
            client_secret='secret')
        self.assertEqual(oauth2.storage, storage_mock)

    def test_explicit_scopes(self):
        oauth2 = FlaskOAuth2(
            flask.Flask(__name__), scopes=['1', '2'], client_id='id',
            client_secret='secret')
        self.assertEqual(oauth2.scopes, ['1', '2'])

    def test_bad_client_secrets(self):
        return_val = (
            'other',
            {'client_id': 'id', 'client_secret': 'secret'})

        with mock.patch('oauth2client.clientsecrets.loadfile',
                        return_value=return_val):
            self.assertRaises(
                ValueError,
                FlaskOAuth2,
                flask.Flask(__name__), client_secrets_file='file.json')

    def test_app_configuration(self):
        app = flask.Flask(__name__)
        app.config['GOOGLE_OAUTH2_CLIENT_ID'] = 'id'
        app.config['GOOGLE_OAUTH2_CLIENT_SECRET'] = 'secret'

        oauth2 = FlaskOAuth2(app)

        self.assertEqual(oauth2.client_id, 'id')
        self.assertEqual(oauth2.client_secret, 'secret')

        return_val = (
            clientsecrets.TYPE_WEB,
            {'client_id': 'id2', 'client_secret': 'secret2'})

        with mock.patch('oauth2client.clientsecrets.loadfile',
                        return_value=return_val):

            app = flask.Flask(__name__)
            app.config['GOOGLE_OAUTH2_CLIENT_SECRETS_FILE'] = 'file.json'
            oauth2 = FlaskOAuth2(app)

            self.assertEqual(oauth2.client_id, 'id2')
            self.assertEqual(oauth2.client_secret, 'secret2')

    def test_no_configuration(self):
        self.assertRaises(
            ValueError,
            FlaskOAuth2,
            flask.Flask(__name__))

    def test_create_flow(self):
        with self.app.test_request_context():
            flow = self.oauth2._make_flow()
            state = json.loads(flow.params['state'])
            self.assertTrue('google_oauth2_csrf_token' in flask.session)
            self.assertEqual(
                flask.session['google_oauth2_csrf_token'], state['csrf_token'])
            self.assertEqual(flow.client_id, self.oauth2.client_id)
            self.assertEqual(flow.client_secret, self.oauth2.client_secret)
            self.assertTrue('http' in flow.redirect_uri)
            self.assertTrue('oauth2callback' in flow.redirect_uri)

            flow = self.oauth2._make_flow(return_url='/return_url')
            state = json.loads(flow.params['state'])
            self.assertEqual(state['return_url'], '/return_url')

            flow = self.oauth2._make_flow(extra_arg='test')
            self.assertEqual(flow.params['extra_arg'], 'test')

        # Test extra args specified in the constructor.
        app = flask.Flask(__name__)
        app.config['SECRET_KEY'] = 'notasecert'
        oauth2 = FlaskOAuth2(
            app, client_id='client_id', client_secret='secret',
            extra_arg='test')

        with app.test_request_context():
            flow = oauth2._make_flow()
            self.assertEqual(flow.params['extra_arg'], 'test')

    def test_authorize_view(self):
        with self.app.test_client() as c:
            rv = c.get('/oauth2authorize')
            location = rv.headers['Location']
            q = urlparse.parse_qs(location.split('?', 1)[1])
            state = json.loads(q['state'][0])

            self.assertTrue(GOOGLE_AUTH_URI in location)
            self.assertFalse(self.oauth2.client_secret in location)
            self.assertTrue(self.oauth2.client_id in q['client_id'])
            self.assertEqual(
                flask.session['google_oauth2_csrf_token'], state['csrf_token'])
            self.assertEqual(state['return_url'], '/')

        with self.app.test_client() as c:
            rv = c.get('/oauth2authorize?return_url=/test')
            location = rv.headers['Location']
            q = urlparse.parse_qs(location.split('?', 1)[1])
            state = json.loads(q['state'][0])
            self.assertEqual(state['return_url'], '/test')

        with self.app.test_client() as c:
            rv = c.get('/oauth2authorize?extra_param=test')
            location = rv.headers['Location']
            self.assertTrue('extra_param=test' in location)

    def test_callback_view(self):
        self.oauth2.storage = mock.Mock()

        with self.app.test_client() as c:
            with Http2Mock() as http:
                with c.session_transaction() as session:
                    session['google_oauth2_csrf_token'] = 'tokenz'

                state = json.dumps({
                    'csrf_token': 'tokenz',
                    'return_url': '/return_url'
                })

                rv = c.get('/oauth2callback?state=%s&code=codez' % state)

                self.assertEqual(rv.status_code, httplib.FOUND)
                self.assertTrue('/return_url' in rv.headers['Location'])
                self.assertTrue(self.oauth2.client_secret in http.body)
                self.assertTrue('codez' in http.body)
                self.assertTrue(self.oauth2.storage.put.called)

    def test_authorize_callback(self):
        self.oauth2.authorize_callback = mock.Mock()
        self.test_callback_view()
        self.assertTrue(self.oauth2.authorize_callback.called)

    def test_callback_view_errors(self):
        # Error supplied to callback
        with self.app.test_client() as c:
            with c.session_transaction() as session:
                session['google_oauth2_csrf_token'] = 'tokenz'

            rv = c.get('/oauth2callback?state={}&error=something')
            self.assertEqual(rv.status_code, httplib.BAD_REQUEST)
            self.assertTrue('something' in rv.data.decode('utf-8'))

        # CSRF mismatch
        with self.app.test_client() as c:
            with c.session_transaction() as session:
                session['google_oauth2_csrf_token'] = 'goodstate'

            state = json.dumps({
                'csrf_token': 'badstate',
                'return_url': '/return_url'
            })

            rv = c.get('/oauth2callback?state=%s&code=codez' % state)
            self.assertEqual(rv.status_code, httplib.BAD_REQUEST)

        # KeyError, no CSRF state.
        with self.app.test_client() as c:
            rv = c.get('/oauth2callback?state={}&code=codez')
            self.assertEqual(rv.status_code, httplib.BAD_REQUEST)

        # Code exchange error
        with self.app.test_client() as c:
            with Http2Mock(status=500):
                with c.session_transaction() as session:
                    session['google_oauth2_csrf_token'] = 'tokenz'

                state = json.dumps({
                    'csrf_token': 'tokenz',
                    'return_url': '/return_url'
                })

                rv = c.get('/oauth2callback?state=%s&code=codez' % state)
                self.assertEqual(rv.status_code, httplib.BAD_REQUEST)

        # Invalid state json
        with self.app.test_client() as c:
            with c.session_transaction() as session:
                session['google_oauth2_csrf_token'] = 'tokenz'

            state = '[{'
            rv = c.get('/oauth2callback?state=%s&code=codez' % state)
            self.assertEqual(rv.status_code, httplib.BAD_REQUEST)

    def test_no_credentials(self):
        with self.app.test_request_context():
            self.assertFalse(self.oauth2.has_credentials())
            self.assertTrue(self.oauth2.credentials is None)
            self.assertTrue(self.oauth2.user_id is None)
            self.assertTrue(self.oauth2.email is None)
            self.assertRaises(
                ValueError,
                self.oauth2.http)
            self.assertFalse(self.oauth2.storage.get())
            self.oauth2.storage.delete()

    def test_with_credentials(self):
        credentials = self._generate_credentials()
        with self.app.test_request_context():
            self.oauth2.storage.put(credentials)
            self.assertEqual(
                self.oauth2.credentials.access_token, credentials.access_token)
            self.assertEqual(
                self.oauth2.credentials.refresh_token,
                credentials.refresh_token)
            self.assertEqual(self.oauth2.user_id, '123')
            self.assertEqual(self.oauth2.email, 'user@example.com')
            self.assertTrue(self.oauth2.http())

    def test_bad_id_token(self):
        credentials = self._generate_credentials()
        credentials.id_token = {}
        with self.app.test_request_context():
            self.oauth2.storage.put(credentials)
            self.assertTrue(self.oauth2.user_id is None)
            self.assertTrue(self.oauth2.email is None)

    def test_required(self):
        @self.app.route('/protected')
        @self.oauth2.required
        def index():
            return 'Hello'

        # No credentials, should redirect
        with self.app.test_client() as c:
            rv = c.get('/protected')
            self.assertEqual(rv.status_code, httplib.FOUND)
            self.assertTrue('oauth2authorize' in rv.headers['Location'])
            self.assertTrue('protected' in rv.headers['Location'])

        credentials = self._generate_credentials()

        # With credentials, should allow
        with self.app.test_client() as c:
            with c.session_transaction() as session:
                session['google_oauth2_credentials'] = credentials.to_json()

            rv = c.get('/protected')
            self.assertEqual(rv.status_code, httplib.OK)
            self.assertTrue('Hello' in rv.data.decode('utf-8'))

    def test_incremental_auth(self):
        self.app = flask.Flask(__name__)
        self.app.testing = True
        self.app.config['SECRET_KEY'] = 'notasecert'
        self.oauth2 = FlaskOAuth2(
            self.app,
            client_id='client_idz',
            client_secret='client_secretz',
            include_granted_scopes=True)

        @self.app.route('/one')
        @self.oauth2.required(scopes=['one'])
        def one():
            return 'Hello'

        @self.app.route('/two')
        @self.oauth2.required(scopes=['two', 'three'])
        def two():
            return 'Hello'

        # No credentials, should redirect
        with self.app.test_client() as c:
            rv = c.get('/one')
            self.assertTrue('one' in rv.headers['Location'])
            self.assertEqual(rv.status_code, httplib.FOUND)

        # Credentials for one. /one should allow, /two should redirect.
        credentials = self._generate_credentials(scopes=['one'])

        with self.app.test_client() as c:
            with c.session_transaction() as session:
                session['google_oauth2_credentials'] = credentials.to_json()

            rv = c.get('/one')
            self.assertEqual(rv.status_code, httplib.OK)

            rv = c.get('/two')
            self.assertTrue('two' in rv.headers['Location'])
            self.assertEqual(rv.status_code, httplib.FOUND)

            # Starting the authorization flow should include the
            # include_granted_scopes parameter as well as the scopes.
            rv = c.get(rv.headers['Location'][17:])
            q = urlparse.parse_qs(rv.headers['Location'].split('?', 1)[1])
            self.assertTrue('include_granted_scopes' in q)
            self.assertEqual(q['scope'][0], 'email one two three')

        # Actually call two() without a redirect.
        credentials2 = self._generate_credentials(scopes=['two', 'three'])
        with self.app.test_client() as c:
            with c.session_transaction() as session:
                session['google_oauth2_credentials'] = credentials2.to_json()

            rv = c.get('/two')
            self.assertEqual(rv.status_code, httplib.OK)

    def test_refresh(self):
        with self.app.test_request_context():
            with mock.patch('flask.session'):
                self.oauth2.storage.put(self._generate_credentials())

                self.oauth2.credentials.refresh(
                    Http2Mock(access_token='new_token'))

                self.assertEqual(
                    self.oauth2.storage.get().access_token, 'new_token')

    def test_delete(self):
        with self.app.test_request_context():

            self.oauth2.storage.put(self._generate_credentials())
            self.oauth2.storage.delete()

            self.assertFalse('google_oauth2_credentials' in flask.session)


if __name__ == '__main__':  # pragma: NO COVER
    unittest.main()
