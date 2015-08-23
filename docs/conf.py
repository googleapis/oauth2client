# -*- coding: utf-8 -*-
#
# oauth2client documentation build configuration file, created by
# sphinx-quickstart on Wed Dec 17 23:13:19 2014.
#

import os
from pkg_resources import get_distribution
import sys

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
sys.path.insert(0, os.path.abspath('..'))

# -- General configuration ------------------------------------------------

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.coverage',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
]
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

# General information about the project.
project = u'oauth2client'
copyright = u'2014, Google, Inc'

# Version info
distro = get_distribution('oauth2client')
version = distro.version
release = distro.version

exclude_patterns = ['_build']

# In order to load django before 1.7, we need to create a faux
# settings module and load it. This assumes django has been installed
# (but it must be for the docs to build), so if it has not already
# been installed run `pip install -r docs/requirements.txt`.
import django
if django.VERSION[1] < 7:
    sys.path.insert(0, '.')
    os.environ['DJANGO_SETTINGS_MODULE'] = 'django_settings'

# -- Options for HTML output ----------------------------------------------

# We want to set the RTD theme, but not if we're on RTD.
if os.environ.get('READTHEDOCS', None) == 'True':
    # Download the GAE SDK if we are building on READTHEDOCS.
    docs_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.abspath(os.path.join(docs_dir, '..'))
    gae_dir = os.path.join(root_dir, 'google_appengine')
    if not os.path.isdir(gae_dir):
        scripts_dir = os.path.join(root_dir, 'scripts')
        sys.path.append(scripts_dir)
        import fetch_gae_sdk
        # The first argument is the script name and the second is
        # the destination dir (where google_appengine is downloaded).
        result = fetch_gae_sdk.main([None, root_dir])
        if result not in (0, None):
            sys.stderr.write('Result failed %d\n' % (result,))
            sys.exit(result)
        # Allow imports from the GAE directory as well.
        sys.path.append(gae_dir)
else:
    import sphinx_rtd_theme
    html_theme = 'sphinx_rtd_theme'
    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]

# The name of an image file (within the static path) to use as favicon of the
# docs.  This file should be a Windows icon file (.ico) being 16x16 or 32x32
# pixels large.
html_favicon = '_static/favicon.ico'

html_static_path = ['_static']
html_logo = '_static/google_logo.png'
htmlhelp_basename = 'oauth2clientdoc'

# -- Options for LaTeX output ---------------------------------------------

latex_elements = {}
latex_documents = [
    ('index', 'oauth2client.tex', u'oauth2client Documentation',
     u'Google, Inc.', 'manual'),
]

# -- Options for manual page output ---------------------------------------

man_pages = [
    ('index', 'oauth2client', u'oauth2client Documentation',
     [u'Google, Inc.'], 1)
]

# -- Options for Texinfo output -------------------------------------------

texinfo_documents = [
    ('index', 'oauth2client', u'oauth2client Documentation',
     u'Google, Inc.', 'oauth2client', 'One line description of project.',
     'Miscellaneous'),
]
