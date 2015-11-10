"""Unit tests for oauth2client.multistore_file."""

import errno
import os
import tempfile
import unittest

from oauth2client import multistore_file


class _MockLockedFile(object):

    def __init__(self, filename_str, error_code):
        self.filename_str = filename_str
        self.error_code = error_code
        self.open_and_lock_called = False

    def open_and_lock(self):
        self.open_and_lock_called = True
        raise IOError(self.error_code, '')

    def is_locked(self):
        return False

    def filename(self):
        return self.filename_str


class MultistoreFileTests(unittest.TestCase):

    def test_lock_file_raises_ioerror(self):
        filehandle, filename = tempfile.mkstemp()
        os.close(filehandle)

        try:
            for error_code in (errno.EDEADLK, errno.ENOSYS, errno.ENOLCK):
                multistore = multistore_file._MultiStore(filename)
                multistore._file = _MockLockedFile(filename, error_code)
                # Should not raise even though the underlying file class did.
                multistore._lock()
                self.assertTrue(multistore._file.open_and_lock_called)
        finally:
            os.unlink(filename)
