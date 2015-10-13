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

from oauth2client import client


def get_storage(request):
    # TODO(issue 319): Make this pluggable with different storage providers
    # https://github.com/google/oauth2client/issues/319
    """ Gets a Credentials storage object for the Django OAuth2 Helper object
    :param request: Reference to the current request object
    :return: A OAuth2Client Storage implementation based on sessions
    """
    return DjangoSessionStorage(request.session)

_CREDENTIALS_KEY = 'google_oauth2_credentials'


class DjangoSessionStorage(client.Storage):
    """Storage implementation that uses Django sessions."""

    def __init__(self, session):
        self.session = session

    def locked_get(self):
        serialized = self.session.get(_CREDENTIALS_KEY)

        if serialized is None:
            return None

        credentials = client.OAuth2Credentials.from_json(serialized)
        credentials.set_store(self)

        return credentials

    def locked_put(self, credentials):
        self.session[_CREDENTIALS_KEY] = credentials.to_json()

    def locked_delete(self):
        if _CREDENTIALS_KEY in self.session:
            del self.session[_CREDENTIALS_KEY]
