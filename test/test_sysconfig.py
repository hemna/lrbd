
import tempfile
import unittest

from lrbd import main


class SysconfigTestCase(unittest.TestCase):

    def test_sysconfig_options(self):
        data = '''LRBD_OPTIONS="-v"'''
        with tempfile.NamedTemporaryFile(suffix=".tmp") as tmpfile:
            tmpfile.write(data)
            tmpfile.flush()
            result = main.sysconfig_options(tmpfile.name)
            assert result == ['-v']

    def test_sysconfig_options_missing_variable(self):
        data = '''#Just a comment'''
        with tempfile.NamedTemporaryFile(suffix=".tmp") as tmpfile:
            tmpfile.write(data)
            tmpfile.flush()
            result = main.sysconfig_options(tmpfile.name)
            assert result == []
