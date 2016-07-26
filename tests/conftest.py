# Copyright 2016 Google Inc. All rights reserved.
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

"""Common testing tools for OAuth2Client tests."""

import sys

from six.moves import reload_module

from oauth2client import util


def set_up_gae_environment(gae_sdk_path):
    """Set up appengine SDK third-party imports."""
    if 'google' in sys.modules:
        # Some packages, such as protobuf, clobber the google
        # namespace package. This prevents that.
        reload_module(sys.modules['google'])

    # This sets up google-provided libraries.
    sys.path.insert(0, gae_sdk_path)
    import dev_appserver
    dev_appserver.fix_sys_path()

    # Fixes timezone and other os-level items.
    import google.appengine.tools.os_compat  # noqa: unused import


def pytest_configure(config):
    """Pytest hook function for setting up test session."""
    # Set up Google SDK modules unless specified not to
    if not config.option.no_gae:
        set_up_gae_environment(config.option.sdk_path)
    # Default of POSITIONAL_WARNING is too verbose for testing
    util.positional_parameters_enforcement = util.POSITIONAL_EXCEPTION
