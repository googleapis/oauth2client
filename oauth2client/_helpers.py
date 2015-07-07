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
"""Helper functions for commonly used utilities."""

import base64
import json
import six


def _parse_pem_key(raw_key_input):
  """Identify and extract PEM keys.

  Determines whether the given key is in the format of PEM key, and extracts
  the relevant part of the key if it is.

  Args:
    raw_key_input: The contents of a private key file (either PEM or PKCS12).

  Returns:
    string, The actual key if the contents are from a PEM file, or else None.
  """
  offset = raw_key_input.find(b'-----BEGIN ')
  if offset != -1:
    return raw_key_input[offset:]


def _json_encode(data):
  return json.dumps(data, separators=(',', ':'))


def _urlsafe_b64encode(raw_bytes):
  if isinstance(raw_bytes, six.text_type):
    raw_bytes = raw_bytes.encode('utf-8')
  return base64.urlsafe_b64encode(raw_bytes).decode('ascii').rstrip('=')


def _urlsafe_b64decode(b64string):
  # Guard against unicode strings, which base64 can't handle.
  if isinstance(b64string, six.text_type):
    b64string = b64string.encode('ascii')
  padded = b64string + b'=' * (4 - len(b64string) % 4)
  return base64.urlsafe_b64decode(padded)
