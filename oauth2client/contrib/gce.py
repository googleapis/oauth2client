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

"""Utilities for Google Compute Engine

Utilities for making it easier to use OAuth 2.0 on Google Compute Engine.
"""

import json
import logging
import warnings

import httplib2

from oauth2client._helpers import _from_bytes
from oauth2client import util
from oauth2client.client import AssertionCredentials
from oauth2client.client import HttpAccessTokenRefreshError
from oauth2client.contrib import _metadata


__author__ = 'jcgregorio@google.com (Joe Gregorio)'

logger = logging.getLogger(__name__)

_SCOPES_WARNING = """\
You have requested explicit scopes to be used with a GCE service account.
Using this argument will have no effect on the actual scopes for tokens
requested. These scopes are set at VM instance creation time and
can't be overridden in the request.
"""


class AppAssertionCredentials(AssertionCredentials):
    """Credentials object for Compute Engine Assertion Grants

    This object will allow a Compute Engine instance to identify itself to
    Google and other OAuth 2.0 servers that can verify assertions. It can be
    used for the purpose of accessing data stored under an account assigned to
    the Compute Engine instance itself.

    This credential does not require a flow to instantiate because it
    represents a two legged flow, and therefore has all of the required
    information to generate and refresh its own access tokens.
    """

    @util.positional(2)
    def __init__(self, scope='', **kwargs):
        """Constructor for AppAssertionCredentials

        Args:
            scope: string or iterable of strings, scope(s) of the credentials
                   being requested. Using this argument will have no effect on
                   the actual scopes for tokens requested. These scopes are
                   set at VM instance creation time and won't change.
        """
        if scope:
            warnings.warn(_SCOPES_WARNING)
        # This is just provided for backwards compatibility, but is not
        # used by this class.
        self.scope = util.scopes_to_string(scope)
        self.kwargs = kwargs

        # Assertion type is no longer used, but still in the
        # parent class signature.
        super(AppAssertionCredentials, self).__init__(None)

        # Cache until Metadata Server supports Cache-Control Header
        self._service_account_email = None

    @classmethod
    def from_json(cls, json_data):
        data = json.loads(_from_bytes(json_data))
        return AppAssertionCredentials(data['scope'])

    def _refresh(self, http_request):
        """Refreshes the access_token.

        Skip all the storage hoops and just refresh using the API.

        Args:
            http_request: callable, a callable that matches the method
                          signature of httplib2.Http.request, used to make
                          the refresh request.

        Raises:
            HttpAccessTokenRefreshError: When the refresh fails.
        """
        try:
            self.access_token, self.token_expiry = _metadata.get_token(
                http_request=http_request)
        except httplib2.HttpLib2Error as e:
            raise HttpAccessTokenRefreshError(str(e))

    @property
    def serialization_data(self):
        raise NotImplementedError(
            'Cannot serialize credentials for GCE service accounts.')

    def create_scoped_required(self):
        return False

    def create_scoped(self, scopes):
        return AppAssertionCredentials(scopes, **self.kwargs)

    def sign_blob(self, blob):
        """Cryptographically sign a blob (of bytes).

        This method is provided to support a common interface, but
        the actual key used for a Google Compute Engine service account
        is not available, so it can't be used to sign content.

        Args:
            blob: bytes, Message to be signed.

        Raises:
            NotImplementedError, always.
        """
        raise NotImplementedError(
            'Compute Engine service accounts cannot sign blobs')

    @property
    def service_account_email(self):
        """Get the email for the current service account.

        Uses the Google Compute Engine metadata service to retrieve the email
        of the default service account.

        Returns:
            string, The email associated with the Google Compute Engine
            service account.

        Raises:
            AttributeError, if the email can not be retrieved from the Google
            Compute Engine metadata service.
        """
        if self._service_account_email is None:
            self._service_account_email = (
                _metadata.get_service_account_info()['email'])
        return self._service_account_email
