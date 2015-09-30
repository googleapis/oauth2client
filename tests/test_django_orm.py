#!/usr/bin/python2.4
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

"""Discovery document tests

Unit tests for objects created from discovery documents.
"""

import base64
import imp
import os
import pickle
import sys
import unittest

from oauth2client.client import Credentials
from oauth2client.client import Flow

# Mock a Django environment
from django.conf import global_settings
global_settings.SECRET_KEY = 'NotASecret'
os.environ['DJANGO_SETTINGS_MODULE'] = 'django_settings'
sys.modules['django_settings'] = django_settings = imp.new_module(
    'django_settings')
django_settings.SECRET_KEY = 'xyzzy'
from django.db import models

from oauth2client.django_orm import CredentialsField
from oauth2client.django_orm import FlowField
from oauth2client._helpers import _from_bytes, _to_bytes

__author__ = 'conleyo@google.com (Conley Owens)'


class TestCredentialsField(unittest.TestCase):

    def setUp(self):
        self.field = CredentialsField()
        self.credentials = Credentials()
        self.pickle = base64.b64encode(pickle.dumps(self.credentials))

    def test_field_is_text(self):
        self.assertEquals(self.field.get_internal_type(), 'TextField')

    def test_field_unpickled(self):
        self.assertTrue(isinstance(self.field.to_python(self.pickle),
                                   Credentials))

    def test_field_unpickled_none(self):
        self.assertEqual(self.field.to_python(None), None)

    def test_field_pickled(self):
        prep_value = self.field.get_db_prep_value(self.credentials,
                                                  connection=None)
        self.assertEqual(_to_bytes(prep_value), self.pickle)


class TestCredentialsFieldViaModel(unittest.TestCase):

    class TestModel(models.Model):
        credentials = CredentialsField()

    def setUp(self):
        self.model = self.TestModel()
        # using the meta api:
        # https://docs.djangoproject.com/en/1.8/ref/models/meta/#field-access-api
        self.field = self.model._meta.get_field('credentials')
        self.credentials = Credentials()
        self.pickle_str = _from_bytes(base64.b64encode(pickle.dumps(
            self.credentials
        )))

    def test_field_value_to_string(self):
        self.model.credentials = self.credentials
        value_str = self.field.value_to_string(self.model)
        self.assertEqual(value_str, self.pickle_str)

    def test_field_value_to_string_none(self):
        self.model.credentials = None
        value_str = self.field.value_to_string(self.model)
        self.assertEqual(value_str, None)


class TestFlowField(unittest.TestCase):
    def setUp(self):
        self.field = FlowField()
        self.flow = Flow()
        self.pickle = base64.b64encode(pickle.dumps(self.flow))

    def test_field_is_text(self):
        self.assertEquals(self.field.get_internal_type(), 'TextField')

    def test_field_unpickled(self):
        self.assertTrue(isinstance(self.field.to_python(self.pickle), Flow))

    def test_field_pickled(self):
        prep_value = self.field.get_db_prep_value(self.flow, connection=None)
        self.assertEqual(prep_value, self.pickle)


if __name__ == '__main__':  # pragma: NO COVER
    unittest.main()
