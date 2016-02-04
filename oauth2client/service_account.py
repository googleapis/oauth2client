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

"""oauth2client Service account credentials class."""

import base64
import datetime
import json
import time

from oauth2client import GOOGLE_REVOKE_URI
from oauth2client import GOOGLE_TOKEN_URI
from oauth2client._helpers import _json_encode
from oauth2client._helpers import _from_bytes
from oauth2client._helpers import _to_bytes
from oauth2client._helpers import _urlsafe_b64encode
from oauth2client import util
from oauth2client.client import AssertionCredentials
from oauth2client.client import EXPIRY_FORMAT
from oauth2client import crypt


class _ServiceAccountCredentials(AssertionCredentials):
    """Class representing a service account (signed JWT) credential."""

    MAX_TOKEN_LIFETIME_SECS = 3600  # 1 hour in seconds

    NON_SERIALIZED_MEMBERS =  (
        frozenset(['_signer']) |
        AssertionCredentials.NON_SERIALIZED_MEMBERS)

    def __init__(self, service_account_id, service_account_email,
                 private_key_id, private_key_pkcs8_text, scopes,
                 user_agent=None, token_uri=GOOGLE_TOKEN_URI,
                 revoke_uri=GOOGLE_REVOKE_URI, **kwargs):

        super(_ServiceAccountCredentials, self).__init__(
            None, user_agent=user_agent, token_uri=token_uri,
            revoke_uri=revoke_uri)

        self._service_account_id = service_account_id
        self._service_account_email = service_account_email
        self._private_key_id = private_key_id
        self._private_key_pkcs8_text = private_key_pkcs8_text
        self._signer = crypt.Signer.from_string(self._private_key_pkcs8_text)
        self._scopes = util.scopes_to_string(scopes)
        self._user_agent = user_agent
        self._token_uri = token_uri
        self._revoke_uri = revoke_uri
        self._kwargs = kwargs

    def _generate_assertion(self):
        """Generate the assertion that will be used in the request."""
        now = int(time.time())
        payload = {
            'aud': self._token_uri,
            'scope': self._scopes,
            'iat': now,
            'exp': now + self.MAX_TOKEN_LIFETIME_SECS,
            'iss': self._service_account_email,
        }
        payload.update(self._kwargs)
        return crypt.make_signed_jwt(self._signer, payload,
                                     key_id=self._private_key_id)

    def sign_blob(self, blob):
        return self._private_key_id, self._signer.sign(blob)

    @property
    def service_account_email(self):
        return self._service_account_email

    @property
    def serialization_data(self):
        return {
            'type': 'service_account',
            'client_id': self._service_account_id,
            'client_email': self._service_account_email,
            'private_key_id': self._private_key_id,
            'private_key': self._private_key_pkcs8_text
        }

    @classmethod
    def from_json(cls, s):
        data = json.loads(_from_bytes(s))

        credentials = cls(
            service_account_id=data['_service_account_id'],
            service_account_email=data['_service_account_email'],
            private_key_id=data['_private_key_id'],
            private_key_pkcs8_text=data['_private_key_pkcs8_text'],
            scopes=[],
            user_agent=data['_user_agent'])
        credentials.invalid = data['invalid']
        credentials.access_token = data['access_token']
        token_expiry = data.get('token_expiry', None)
        if token_expiry is not None:
            credentials.token_expiry = datetime.datetime.strptime(
                token_expiry, EXPIRY_FORMAT)
        return credentials

    def create_scoped_required(self):
        return not self._scopes

    def create_scoped(self, scopes):
        return _ServiceAccountCredentials(self._service_account_id,
                                          self._service_account_email,
                                          self._private_key_id,
                                          self._private_key_pkcs8_text,
                                          scopes,
                                          user_agent=self._user_agent,
                                          token_uri=self._token_uri,
                                          revoke_uri=self._revoke_uri,
                                          **self._kwargs)
