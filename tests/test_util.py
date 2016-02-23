"""Unit tests for oauth2client.util."""

import unittest

from oauth2client import util


__author__ = 'jcgregorio@google.com (Joe Gregorio)'


class ScopeToStringTests(unittest.TestCase):

    def test_iterables(self):
        cases = [
            ('', ''),
            ('', ()),
            ('', []),
            ('', ('',)),
            ('', ['', ]),
            ('a', ('a',)),
            ('b', ['b', ]),
            ('a b', ['a', 'b']),
            ('a b', ('a', 'b')),
            ('a b', 'a b'),
            ('a b', (s for s in ['a', 'b'])),
        ]
        for expected, case in cases:
            self.assertEqual(expected, util.scopes_to_string(case))


class StringToScopeTests(unittest.TestCase):

    def test_conversion(self):
        cases = [
            (['a', 'b'], ['a', 'b']),
            ('', []),
            ('a', ['a']),
            ('a b c d e f', ['a', 'b', 'c', 'd', 'e', 'f']),
        ]

        for case, expected in cases:
            self.assertEqual(expected, util.string_to_scopes(case))


if __name__ == '__main__':  # pragma: NO COVER
    unittest.main()
