# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit test for django_util views"""

import copy
import json

import django
from django import http
import django.conf
from django.contrib.auth.models import AnonymousUser, User
import mock
from six.moves import reload_module

from tests.contrib.django_util import TestWithDjangoEnvironment
from tests.contrib.django_util.models import CredentialsModel

from oauth2client.client import FlowExchangeError, OAuth2WebServerFlow
import oauth2client.contrib.django_util
from oauth2client.contrib.django_util import views
from oauth2client.contrib.django_util.models import CredentialsField


class OAuth2AuthorizeTest(TestWithDjangoEnvironment):

    def setUp(self):
        super(OAuth2AuthorizeTest, self).setUp()
        self.save_settings = copy.deepcopy(django.conf.settings)
        reload_module(oauth2client.contrib.django_util)
        self.user = User.objects.create_user(
          username='bill', email='bill@example.com', password='hunter2')

    def tearDown(self):
        django.conf.settings = copy.deepcopy(self.save_settings)

    def test_authorize_works(self):
        request = self.factory.get('oauth2/oauth2authorize')
        request.session = self.session
        request.user = self.user
        response = views.oauth2_authorize(request)
        self.assertIsInstance(response, http.HttpResponseRedirect)

    def test_authorize_anonymous_user(self):
        request = self.factory.get('oauth2/oauth2authorize')
        request.session = self.session
        request.user = AnonymousUser()
        response = views.oauth2_authorize(request)
        self.assertIsInstance(response, http.HttpResponseRedirect)

    def test_authorize_works_explicit_return_url(self):
        request = self.factory.get('oauth2/oauth2authorize',
                                   data={'return_url': '/return_endpoint'})
        request.session = self.session
        request.user = self.user
        response = views.oauth2_authorize(request)
        self.assertIsInstance(response, http.HttpResponseRedirect)


class Oauth2AuthorizeStorageModelTest(TestWithDjangoEnvironment):

    def setUp(self):
        super(Oauth2AuthorizeStorageModelTest, self).setUp()
        self.save_settings = copy.deepcopy(django.conf.settings)

        STORAGE_MODEL = {
            'model': 'tests.contrib.django_util.models.CredentialsModel',
            'user_property': 'user_id',
            'credentials_property': 'credentials'
        }
        django.conf.settings.GOOGLE_OAUTH2_STORAGE_MODEL = STORAGE_MODEL

        # OAuth2 Settings gets configured based on Django settings
        # at import time, so in order for us to reload the settings
        # we need to reload the module
        reload_module(oauth2client.contrib.django_util)
        self.user = User.objects.create_user(
            username='bill', email='bill@example.com', password='hunter2')

    def tearDown(self):
        django.conf.settings = copy.deepcopy(self.save_settings)

    def test_authorize_works(self):
        request = self.factory.get('oauth2/oauth2authorize')
        request.session = self.session
        request.user = self.user
        response = views.oauth2_authorize(request)
        self.assertIsInstance(response, http.HttpResponseRedirect)
        # redirects to Google oauth
        self.assertIn('accounts.google.com', response.url)

    def test_authorize_anonymous_user_redirects_login(self):
        request = self.factory.get('oauth2/oauth2authorize')
        request.session = self.session
        request.user = AnonymousUser()
        response = views.oauth2_authorize(request)
        self.assertIsInstance(response, http.HttpResponseRedirect)
        # redirects to Django login
        self.assertIn(django.conf.settings.LOGIN_URL, response.url)

    def test_authorize_works_explicit_return_url(self):
        request = self.factory.get('oauth2/oauth2authorize',
                                   data={'return_url': '/return_endpoint'})
        request.session = self.session
        request.user = self.user
        response = views.oauth2_authorize(request)
        self.assertIsInstance(response, http.HttpResponseRedirect)

    def test_authorized_user_not_logged_in_redirects(self):
        request = self.factory.get('oauth2/oauth2authorize',
                                   data={'return_url': '/return_endpoint'})
        request.session = self.session

        authorized_user = User.objects.create_user(
            username='bill2', email='bill@example.com', password='hunter2')
        credentials = CredentialsField()

        CredentialsModel.objects.create(
            user_id=authorized_user,
            credentials=credentials)

        request.user = authorized_user
        response = views.oauth2_authorize(request)
        self.assertIsInstance(response, http.HttpResponseRedirect)


class Oauth2CallbackTest(TestWithDjangoEnvironment):

    def setUp(self):
        super(Oauth2CallbackTest, self).setUp()
        self.save_settings = copy.deepcopy(django.conf.settings)
        reload_module(oauth2client.contrib.django_util)

        self.CSRF_TOKEN = 'token'
        self.RETURN_URL = 'http://return-url.com'
        self.fake_state = {
            'csrf_token': self.CSRF_TOKEN,
            'return_url': self.RETURN_URL,
            'scopes': django.conf.settings.GOOGLE_OAUTH2_SCOPES
        }
        self.user = User.objects.create_user(
            username='bill', email='bill@example.com', password='hunter2')

    @mock.patch('oauth2client.contrib.django_util.views.pickle')
    def test_callback_works(self, pickle):
        request = self.factory.get('oauth2/oauth2callback', data={
            'state': json.dumps(self.fake_state),
            'code': 123
        })

        self.session['google_oauth2_csrf_token'] = self.CSRF_TOKEN

        flow = OAuth2WebServerFlow(
            client_id='clientid',
            client_secret='clientsecret',
            scope=['email'],
            state=json.dumps(self.fake_state),
            redirect_uri=request.build_absolute_uri("oauth2/oauth2callback"))

        name = 'google_oauth2_flow_{0}'.format(self.CSRF_TOKEN)
        self.session[name] = pickle.dumps(flow)
        flow.step2_exchange = mock.Mock()
        pickle.loads.return_value = flow

        request.session = self.session
        request.user = self.user
        response = views.oauth2_callback(request)
        self.assertIsInstance(response, http.HttpResponseRedirect)
        self.assertEqual(
            response.status_code, django.http.HttpResponseRedirect.status_code)
        self.assertEqual(response['Location'], self.RETURN_URL)

    @mock.patch('oauth2client.contrib.django_util.views.pickle')
    def test_callback_handles_bad_flow_exchange(self, pickle):
        request = self.factory.get('oauth2/oauth2callback', data={
            "state": json.dumps(self.fake_state),
            "code": 123
        })

        self.session['google_oauth2_csrf_token'] = self.CSRF_TOKEN

        flow = OAuth2WebServerFlow(
            client_id='clientid',
            client_secret='clientsecret',
            scope=['email'],
            state=json.dumps(self.fake_state),
            redirect_uri=request.build_absolute_uri('oauth2/oauth2callback'))

        self.session['google_oauth2_flow_{0}'.format(self.CSRF_TOKEN)] \
            = pickle.dumps(flow)

        def local_throws(code):
            raise FlowExchangeError('test')

        flow.step2_exchange = local_throws
        pickle.loads.return_value = flow

        request.session = self.session
        response = views.oauth2_callback(request)
        self.assertIsInstance(response, http.HttpResponseBadRequest)

    def test_error_returns_bad_request(self):
        request = self.factory.get('oauth2/oauth2callback', data={
            'error': 'There was an error in your authorization.',
        })
        response = views.oauth2_callback(request)
        self.assertIsInstance(response, http.HttpResponseBadRequest)
        self.assertIn(b'Authorization failed', response.content)

    def test_no_session(self):
        request = self.factory.get('oauth2/oauth2callback', data={
            'code': 123,
            'state': json.dumps(self.fake_state)
        })

        request.session = self.session
        response = views.oauth2_callback(request)
        self.assertIsInstance(response, http.HttpResponseBadRequest)
        self.assertEqual(
            response.content, b'No existing session for this flow.')

    def test_missing_state_returns_bad_request(self):
        request = self.factory.get('oauth2/oauth2callback', data={
            'code': 123
        })
        self.session['google_oauth2_csrf_token'] = "token"
        request.session = self.session
        response = views.oauth2_callback(request)
        self.assertIsInstance(response, http.HttpResponseBadRequest)

    def test_bad_state(self):
        request = self.factory.get('oauth2/oauth2callback', data={
            'code': 123,
            'state': json.dumps({'wrong': 'state'})
        })
        self.session['google_oauth2_csrf_token'] = 'token'
        request.session = self.session
        response = views.oauth2_callback(request)
        self.assertIsInstance(response, http.HttpResponseBadRequest)
        self.assertEqual(response.content, b'Invalid state parameter.')

    def test_bad_csrf(self):
        request = self.factory.get('oauth2/oauth2callback', data={
            "state": json.dumps(self.fake_state),
            "code": 123
        })
        self.session['google_oauth2_csrf_token'] = 'WRONG TOKEN'
        request.session = self.session
        response = views.oauth2_callback(request)
        self.assertIsInstance(response, http.HttpResponseBadRequest)
        self.assertEqual(response.content, b'Invalid CSRF token.')

    def test_no_saved_flow(self):
        request = self.factory.get('oauth2/oauth2callback', data={
            'state': json.dumps(self.fake_state),
            'code': 123
        })
        self.session['google_oauth2_csrf_token'] = self.CSRF_TOKEN
        self.session['google_oauth2_flow_{0}'.format(self.CSRF_TOKEN)] = None
        request.session = self.session
        response = views.oauth2_callback(request)
        self.assertIsInstance(response, http.HttpResponseBadRequest)
        self.assertEqual(response.content, b'Missing Oauth2 flow.')
