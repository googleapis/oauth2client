# Copyright 2015 Google Inc.  All rights reserved.
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

"""Utilities for the Flask web framework

Provides a Flask extension that makes using OAuth2 web server flow easier.
The extension includes views that handle the entire auth flow and a @required
decorator to automatically ensure that user credentials are available.

To configure::

    from oauth2client.flask_util import UserOAuth2

    app = Flask(__name__)

    app.config['SECRET_KEY'] = 'your-secret-key'

    app.config['OAUTH2_CLIENT_SECRETS_JSON'] = 'client_secrets.json'
    # or, specify the client id and secret separately
    app.config['OAUTH2_CLIENT_ID'] = 'your-client-id'
    app.config['OAUTH2_CLIENT_SECRET'] = 'your-client-secret'

    oauth2 = UserOAuth2(app)


To use::

    # Note that app.route should be the outermost decorator.
    @app.route('/needs_credentials')
    @oauth2.required
    def example():
        # http is authorized with the user's credentials and can be used
        # to make http calls.
        http = oauth2.http()

        # Or, you can access the credentials directly
        credentials = oauth2.credentials


    @app.route('/info')
    @oauth2.required
    def info():
        return "Hello, {}".format(oauth2.email)

    @app.route('/optional')
    def optional():
        if oauth2.has_credentials():
            return 'Credentials found!'
        else:
            return 'No credentials!'

"""

__author__ = 'jonwayne@google.com (Jon Wayne Parrott)'

import hashlib
import json
import os
from functools import wraps

import six.moves.http_client as httplib
import httplib2

try:
    from flask import Blueprint
    from flask import _app_ctx_stack
    from flask import current_app
    from flask import redirect
    from flask import request
    from flask import session
    from flask import url_for
except ImportError:
    raise ImportError('The flask utilities require flask 0.9 or newer.')

from oauth2client.client import FlowExchangeError
from oauth2client.client import OAuth2Credentials
from oauth2client.client import OAuth2WebServerFlow
from oauth2client.client import Storage
from oauth2client import clientsecrets
from oauth2client import util


DEFAULT_SCOPES = ('email',)


class UserOAuth2(object):
    """Flask extension for making OAuth 2.0 easier.

    Configuration values:
        * GOOGLE_OAUTH2_CLIENT_SECRETS_JSON path to a client secrets json file,
            obtained from the credentials screen in the Google Developers
            console.
        * GOOGLE_OAUTH2_CLIENT_ID the oauth2 credentials' client ID. This is
            only needed if OAUTH2_CLIENT_SECRETS_JSON is not specified.
        * GOOGLE_OAUTH2_CLIENT_SECRET the oauth2 credentials' client secret.
            This is only needed if OAUTH2_CLIENT_SECRETS_JSON is not specified.

    If app is specified, all arguments will be passed along to init_app.

    If no app is specified, then you should call init_app in your application
    factory to finish initialization.
    """

    def __init__(self, app=None, *args, **kwargs):
        self.app = app
        if app is not None:
            self.init_app(app, *args, **kwargs)

    def init_app(self, app, scopes=None, client_secrets_file=None,
                 client_id=None, client_secret=None, authorize_callback=None,
                 storage=None, **kwargs):
        """Initialize this extension for the given app.

        Arguments:
            app: A Flask application.
            scopes: Optional list of scopes to authorize.
            client_secrets_file: Path to a file containing client secrets. You
                can also specify the OAUTH2_CLIENT_SECRETS_JSON config value.
            client_id: If not specifying a client secrets file, specify the
                OAuth2 client id. You can also specify the
                GOOGLE_OAUTH2_CLIENT_ID config value. You must also provide a
                client secret.
            client_secret: The OAuth2 client secret. You can also specify the
                GOOGLE_OAUTH2_CLIENT_SECRET config value.
            authorize_callback: A function that is executed after successful
                user authorization.
            storage: A oauth2client.client.Storage subclass for storing the
                credentials. By default, this is a Flask session based storage.
            kwargs: Any additional args are passed along to the Flow
                constructor.
        """
        self.app = app
        self.authorize_callback = authorize_callback
        self.flow_kwargs = kwargs

        if storage is None:
            storage = FlaskSessionStorage()
        self.storage = storage

        if scopes is None:
            scopes = app.config.get('GOOGLE_OAUTH2_SCOPES', DEFAULT_SCOPES)
        self.scopes = scopes

        self._load_config(client_secrets_file, client_id, client_secret)

        app.register_blueprint(self._create_blueprint())

    def _load_config(self, client_secrets_file, client_id, client_secret):
        """Loads oauth2 configuration in order of priority.

        Priority:
            1. Config passed to the constructor or init_app.
            2. Config passed via the GOOGLE_OAUTH2_CLIENT_SECRETS_FILE app
               config.
            3. Config passed via the GOOGLE_OAUTH2_CLIENT_ID and
               GOOGLE_OAUTH2_CLIENT_SECRET app config.

        Raises:
            ValueError if no config could be found.
        """
        if client_id and client_secret:
            self.client_id, self.client_secret = client_id, client_secret
            return

        if client_secrets_file:
            self._load_client_secrets(client_secrets_file)
            return

        if 'GOOGLE_OAUTH2_CLIENT_SECRETS_FILE' in self.app.config:
            self._load_client_secrets(
                self.app.config['GOOGLE_OAUTH2_CLIENT_SECRETS_FILE'])
            return

        try:
            self.client_id, self.client_secret = (
                self.app.config['GOOGLE_OAUTH2_CLIENT_ID'],
                self.app.config['GOOGLE_OAUTH2_CLIENT_SECRET'])
        except KeyError:
            raise ValueError(
                'OAuth2 configuration could not be found. Either specify the '
                'client_secrets_file or client_id and client_secret or set the'
                'app configuration variables GOOGLE_OAUTH2_CLIENT_SECRETS_FILE '
                'or GOOGLE_OAUTH2_CLIENT_ID and GOOGLE_OAUTH2_CLIENT_SECRET.')

    def _load_client_secrets(self, filename):
        """Loads client secrets from the given filename."""
        client_type, client_info = clientsecrets.loadfile(filename)
        if client_type != clientsecrets.TYPE_WEB:
            raise ValueError(
                'The flow specified in %s is not supported.' % client_type)

        self.client_id = client_info['client_id']
        self.client_secret = client_info['client_secret']

    def _make_flow(self, return_url=None, **kwargs):
        """Creates a Web Server Flow"""
        # Generate a CSRF token to prevent malicious requests.
        csrf_token = hashlib.sha256(os.urandom(1024)).hexdigest()

        session['google_oauth2_csrf_token'] = csrf_token

        state = json.dumps({
            'csrf_token': csrf_token,
            'return_url': return_url
        })

        kw = self.flow_kwargs.copy()
        kw.update(kwargs)

        extra_scopes = util.scopes_to_string(kw.pop('scopes', ''))
        scopes = ' '.join([util.scopes_to_string(self.scopes), extra_scopes])

        return OAuth2WebServerFlow(
            client_id=self.client_id,
            client_secret=self.client_secret,
            scope=scopes,
            state=state,
            redirect_uri=url_for('oauth2.callback', _external=True),
            **kw)

    def _create_blueprint(self):
        bp = Blueprint('oauth2', __name__)
        bp.add_url_rule('/oauth2authorize', 'authorize', self.authorize_view)
        bp.add_url_rule('/oauth2callback', 'callback', self.callback_view)

        return bp

    def authorize_view(self):
        """Flask view that starts the authorization flow by redirecting the
        user to the OAuth2 provider."""
        args = request.args.to_dict()

        return_url = args.pop('return_url', None)
        if return_url is None:
            return_url = request.referrer or '/'

        flow = self._make_flow(return_url=return_url, **args)
        auth_url = flow.step1_get_authorize_url()

        return redirect(auth_url)

    def callback_view(self):
        """Flask view that handles the user's return from the OAuth2 provider
        and exchanges the authorization code for credentials and stores the
        credentials."""
        if 'error' in request.args:
            reason = request.args.get(
                'error_description', request.args.get('error', ''))
            return 'Authorization failed: %s' % reason, httplib.BAD_REQUEST

        try:
            encoded_state = request.args['state']
            server_csrf = session['google_oauth2_csrf_token']
            code = request.args['code']
        except KeyError:
            return 'Invalid request', httplib.BAD_REQUEST

        try:
            state = json.loads(encoded_state)
            client_csrf = state['csrf_token']
            return_url = state['return_url']
        except (ValueError, KeyError):
            return 'Invalid request state', httplib.BAD_REQUEST

        if client_csrf != server_csrf:
            return 'Invalid request state', httplib.BAD_REQUEST

        flow = self._make_flow()

        # Exchange the auth code for credentials.
        try:
            credentials = flow.step2_exchange(code)
        except FlowExchangeError as exchange_error:
            current_app.logger.exception(exchange_error)
            return 'An error occurred: %s' % exchange_error, httplib.BAD_REQUEST

        # Save the credentials to the storage.
        self.storage.put(credentials)

        if self.authorize_callback:
            self.authorize_callback(credentials)

        return redirect(return_url)

    @property
    def credentials(self):
        """The credentials for the current user or None if unavailable."""
        ctx = _app_ctx_stack.top

        if not hasattr(ctx, 'google_oauth2_credentials'):
            ctx.google_oauth2_credentials = self.storage.get()

        return ctx.google_oauth2_credentials

    def has_credentials(self):
        """Returns True if there are valid credentials for the current user."""
        return self.credentials and not self.credentials.invalid

    @property
    def email(self):
        """Returns the user's email address or None if there are no credentials.

        The email address is provided by the current credentials' id_token. This
        should not be used as unique identifier as the user can change their
        email. If you need a unique identifier, use user_id.
        """
        if not self.credentials:
            return None
        try:
            return self.credentials.id_token['email']
        except KeyError:
            current_app.logger.error(
                'Invalid id_token %s', self.credentials.id_token)

    @property
    def user_id(self):
        """Returns the a unique identifier for the user or None if there are no
        credentials.

        The id is provided by the current credentials' id_token.
        """
        if not self.credentials:
            return None
        try:
            return self.credentials.id_token['sub']
        except KeyError:
            current_app.logger.error(
                'Invalid id_token %s', self.credentials.id_token)

    def authorize_url(self, return_url, **kwargs):
        """Creates a URL that can be used to start the authorization flow.

        When the user is directed to the URL, the authorization flow will begin.
        Once complete, the user will be redirected to the specified return URL.

        Any kwargs are passed into the flow constructor.
        """
        return url_for('oauth2.authorize', return_url=return_url, **kwargs)

    def required(self, decorated_function=None, **decorator_kwargs):
        """Decorator to require OAuth2 credentials for a view.

        If credentials are not available for the current user, then they will
        be redirected to the authorization flow. Once complete, the user will
        be redirected back to the original page.
        """
        def curry_wrapper(wrapped_function):
            @wraps(wrapped_function)
            def required_wrapper(*args, **kwargs):
                if not self.has_credentials():
                    if 'return_url' not in decorator_kwargs:
                        decorator_kwargs['return_url'] = request.url
                    return redirect(self.authorize_url(**decorator_kwargs))
                else:
                    return wrapped_function(*args, **kwargs)
            return required_wrapper

        if decorated_function:
            return curry_wrapper(decorated_function)
        else:
            return curry_wrapper

    def http(self, *args, **kwargs):
        """Returns an authorized http instance.

        Can only be called if there are valid credentials for the user, such
        as inside of a view that is decorated with @required.

        Args:
            *args: Positional arguments passed to httplib2.Http constructor.
            **kwargs: Positional arguments passed to httplib2.Http constructor.

        Raises:
            ValueError if no credentials are available.
        """
        if not self.credentials:
            raise ValueError('No credentials available.')
        return self.credentials.authorize(httplib2.Http(*args, **kwargs))


class FlaskSessionStorage(Storage):
    """Storage implementation that uses Flask sessions.

    Note that flask's default sessions are signed but not encrypted. Users
    can see their own credentials and non-https connections can intercept user
    credentials. We strongly recommend using a server-side session
    implementation.
    """
    def locked_get(self):
        serialized = session.get('google_oauth2_credentials')

        if serialized is None:
            return None

        credentials = OAuth2Credentials.from_json(serialized)

        if credentials:
            credentials.set_store(self)

        return credentials

    def locked_put(self, credentials):
        session['google_oauth2_credentials'] = credentials.to_json()

    def locked_delete(self):
        if 'google_oauth2_credentials' in session:
            del session['google_oauth2_credentials']
