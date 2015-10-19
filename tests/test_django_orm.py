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
import datetime
import imp
import os
import pickle
import sys
import unittest

# Mock a Django environment
from django.conf import global_settings
global_settings.SECRET_KEY = 'NotASecret'
os.environ['DJANGO_SETTINGS_MODULE'] = 'django_settings'
sys.modules['django_settings'] = django_settings = imp.new_module(
    'django_settings')
django_settings.SECRET_KEY = 'xyzzy'
from django.db import models

from oauth2client._helpers import _from_bytes
from oauth2client.client import Credentials
from oauth2client.client import Flow
from oauth2client.client import OAuth2Credentials
from oauth2client.django_orm import CredentialsField
from oauth2client.django_orm import FlowField
from oauth2client.django_orm import Storage
from oauth2client import GOOGLE_TOKEN_URI

__author__ = 'conleyo@google.com (Conley Owens)'


class TestCredentialsField(unittest.TestCase):

    def setUp(self):
        self.fake_model = FakeCredentialsModel()
        self.fake_model_field = self.fake_model._meta.get_field('credentials')
        self.field = CredentialsField()
        self.credentials = Credentials()
        self.pickle_str = _from_bytes(
            base64.b64encode(pickle.dumps(self.credentials)))

    def test_field_is_text(self):
        self.assertEquals(self.field.get_internal_type(), 'TextField')

    def test_field_unpickled(self):
        self.assertTrue(isinstance(self.field.to_python(self.pickle_str),
                                   Credentials))

    def test_field_unpickled_none(self):
        self.assertEqual(self.field.to_python(None), None)

    def test_field_pickled(self):
        prep_value = self.field.get_db_prep_value(self.credentials,
                                                  connection=None)
        self.assertEqual(prep_value, self.pickle_str)

    def test_field_value_to_string(self):
        self.fake_model.credentials = self.credentials
        value_str = self.fake_model_field.value_to_string(self.fake_model)
        self.assertEqual(value_str, self.pickle_str)

    def test_field_value_to_string_none(self):
        self.fake_model.credentials = None
        value_str = self.fake_model_field.value_to_string(self.fake_model)
        self.assertEqual(value_str, None)


class TestFlowField(unittest.TestCase):

    class FakeFlowModel(models.Model):
        flow = FlowField()

    def setUp(self):
        self.fake_model = self.FakeFlowModel()
        self.fake_model_field = self.fake_model._meta.get_field('flow')
        self.field = FlowField()
        self.flow = Flow()
        self.pickle_str = _from_bytes(
            base64.b64encode(pickle.dumps(self.flow)))

    def test_field_is_text(self):
        self.assertEquals(self.field.get_internal_type(), 'TextField')

    def test_field_unpickled(self):
        python_val = self.field.to_python(self.pickle_str)
        self.assertTrue(isinstance(python_val, Flow))

    def test_field_pickled(self):
        prep_value = self.field.get_db_prep_value(self.flow, connection=None)
        self.assertEqual(prep_value, self.pickle_str)

    def test_field_value_to_string(self):
        self.fake_model.flow = self.flow
        value_str = self.fake_model_field.value_to_string(self.fake_model)
        self.assertEqual(value_str, self.pickle_str)

    def test_field_value_to_string_none(self):
        self.fake_model.flow = None
        value_str = self.fake_model_field.value_to_string(self.fake_model)
        self.assertEqual(value_str, None)


class TestStorage(unittest.TestCase):

    def setUp(self):
        access_token = 'foo'
        client_id = 'some_client_id'
        client_secret = 'cOuDdkfjxxnv+'
        refresh_token = '1/0/a.df219fjls0'
        token_expiry = datetime.datetime.utcnow()
        user_agent = 'refresh_checker/1.0'
        self.credentials = OAuth2Credentials(
            access_token, client_id, client_secret,
            refresh_token, token_expiry, GOOGLE_TOKEN_URI,
            user_agent)

    def test_constructor(self):
        key_name = 'foo'
        key_value = 'bar'
        property_name = 'credentials'
        storage = Storage(FakeCredentialsModel, key_name,
                          key_value, property_name)

        self.assertEqual(storage.model_class, FakeCredentialsModel)
        self.assertEqual(storage.key_name, key_name)
        self.assertEqual(storage.key_value, key_value)
        self.assertEqual(storage.property_name, property_name)


class FakeCredentialsModel(models.Model):
    credentials = CredentialsField()


if __name__ == '__main__':  # pragma: NO COVER
    unittest.main()
