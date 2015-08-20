# -*- coding: utf-8 -*-
#
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
"""Crypto-related routines for oauth2client."""

import json
import logging
import time

from oauth2client._helpers import _from_bytes
from oauth2client._helpers import _json_encode
from oauth2client._helpers import _to_bytes
from oauth2client._helpers import _urlsafe_b64decode
from oauth2client._helpers import _urlsafe_b64encode


CLOCK_SKEW_SECS = 300  # 5 minutes in seconds
AUTH_TOKEN_LIFETIME_SECS = 300  # 5 minutes in seconds
MAX_TOKEN_LIFETIME_SECS = 86400  # 1 day in seconds

logger = logging.getLogger(__name__)


class AppIdentityError(Exception):
    pass


try:
    from oauth2client._openssl_crypt import OpenSSLVerifier
    from oauth2client._openssl_crypt import OpenSSLSigner
    from oauth2client._openssl_crypt import pkcs12_key_as_pem
except ImportError:
    OpenSSLVerifier = None
    OpenSSLSigner = None


    def pkcs12_key_as_pem(*args, **kwargs):
        raise NotImplementedError('pkcs12_key_as_pem requires OpenSSL.')


try:
    from oauth2client._pycrypto_crypt import PyCryptoVerifier
    from oauth2client._pycrypto_crypt import PyCryptoSigner
except ImportError:
    PyCryptoVerifier = None
    PyCryptoSigner = None


if OpenSSLSigner:
    Signer = OpenSSLSigner
    Verifier = OpenSSLVerifier
elif PyCryptoSigner:
    Signer = PyCryptoSigner
    Verifier = PyCryptoVerifier
else:
    raise ImportError('No encryption library found. Please install either '
                    'PyOpenSSL, or PyCrypto 2.6 or later')


def make_signed_jwt(signer, payload):
    """Make a signed JWT.

    See http://self-issued.info/docs/draft-jones-json-web-token.html.

    Args:
        signer: crypt.Signer, Cryptographic signer.
        payload: dict, Dictionary of data to convert to JSON and then sign.

    Returns:
        string, The JWT for the payload.
    """
    header = {'typ': 'JWT', 'alg': 'RS256'}

    segments = [
      _urlsafe_b64encode(_json_encode(header)),
      _urlsafe_b64encode(_json_encode(payload)),
    ]
    signing_input = b'.'.join(segments)

    signature = signer.sign(signing_input)
    segments.append(_urlsafe_b64encode(signature))

    logger.debug(str(segments))

    return b'.'.join(segments)


def verify_signed_jwt_with_certs(jwt, certs, audience):
    """Verify a JWT against public certs.

    See http://self-issued.info/docs/draft-jones-json-web-token.html.

    Args:
        jwt: string, A JWT.
        certs: dict, Dictionary where values of public keys in PEM format.
        audience: string, The audience, 'aud', that this JWT should contain. If
                  None then the JWT's 'aud' parameter is not verified.

    Returns:
        dict, The deserialized JSON payload in the JWT.

    Raises:
        AppIdentityError if any checks are failed.
    """
    jwt = _to_bytes(jwt)
    segments = jwt.split(b'.')

    if len(segments) != 3:
        raise AppIdentityError('Wrong number of segments in token: %s' % jwt)
    signed = segments[0] + b'.' + segments[1]

    signature = _urlsafe_b64decode(segments[2])

    # Parse token.
    json_body = _urlsafe_b64decode(segments[1])
    try:
        parsed = json.loads(_from_bytes(json_body))
    except:
        raise AppIdentityError('Can\'t parse token: %s' % json_body)

    # Check signature.
    verified = False
    for pem in certs.values():
        verifier = Verifier.from_string(pem, True)
        if verifier.verify(signed, signature):
            verified = True
            break
    if not verified:
        raise AppIdentityError('Invalid token signature: %s' % jwt)

    # Check creation timestamp.
    iat = parsed.get('iat')
    if iat is None:
        raise AppIdentityError('No iat field in token: %s' % json_body)
    earliest = iat - CLOCK_SKEW_SECS

    # Check expiration timestamp.
    now = int(time.time())
    exp = parsed.get('exp')
    if exp is None:
        raise AppIdentityError('No exp field in token: %s' % json_body)
    if exp >= now + MAX_TOKEN_LIFETIME_SECS:
        raise AppIdentityError('exp field too far in future: %s' % json_body)
    latest = exp + CLOCK_SKEW_SECS

    if now < earliest:
        raise AppIdentityError('Token used too early, %d < %d: %s' %
                           (now, earliest, json_body))
    if now > latest:
        raise AppIdentityError('Token used too late, %d > %d: %s' %
                           (now, latest, json_body))

    # Check audience.
    if audience is not None:
        aud = parsed.get('aud')
        if aud is None:
            raise AppIdentityError('No aud field in token: %s' % json_body)
        if aud != audience:
            raise AppIdentityError('Wrong recipient, %s != %s: %s' %
                             (aud, audience, json_body))

    return parsed
