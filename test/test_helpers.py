import mock
from nose import tools
import unittest

from lrbd import content
from lrbd import host
from lrbd import utils


class HelpersTestCase(unittest.TestCase):

    def setUp(self):
        content.Common.config = {}

    def tearDown(self):
        content.Common.config = {}

    @mock.patch('lrbd.utils.popen')
    def test_retry(self, mock_subproc_popen):
        utils.retry(["echo", "hello"])
        assert mock_subproc_popen.called

    @tools.raises(RuntimeError)
    def test_retry_failure(self):
        utils.retry(["/bin/false"])

    @tools.raises(RuntimeError)
    def test_retry_failure_custom(self):
        utils.retry(["/bin/false"],
                    retry_errors=[1], sleep=0.1, retries=2)

    def test_strip_comments(self):
        assert utils.strip_comments("# some comment\n") == ""

    def test_strip_comments_unchanged(self):
        assert utils.strip_comments("some code\n") == "some code\n"

    def test_lstrip_spaces(self):
        assert utils.lstrip_spaces(" " * 12) == ""

    def test_check_keys(self):
        keys = ["a", "b", "c"]
        data = {"a": "", "b": "", "c": ""}
        assert utils.check_keys(keys, data, "test_check_keys") is None

    @tools.raises(ValueError)
    def test_check_keys_exception(self):
        keys = ["a", "b", "c", "d"]
        data = {"a": "", "b": "", "c": ""}
        utils.check_keys(keys, data, "test_check_keys")

    def test_compare_settings(self):
        keys = ["a", "b"]
        current = {"a": "apple", "b": "banana"}
        config = {"a": "apple", "b": "banana", "c": "cherry"}
        assert utils.compare_settings(keys, current, config)

    def test_compare_settings_fails(self):
        keys = ["a", "b"]
        current = {"a": "apple", "b": "banana"}
        config = {"a": "apple", "b": "blueberry", "c": "cherry"}
        assert utils.compare_settings(keys, current, config) is False

    def test_iqn(self):
        entry = {'target': "def"}
        content.Common.config = {'iqns': ["abc"]}
        assert host.iqn(entry) == "def"

    def test_iqn_missing_target(self):
        entry = {}
        content.Common.config['iqns'] = ["abc"]
        # Common.config = { 'iqns' : [ "abc" ] }
        assert host.iqn(entry) == "abc"

    # skip test_addresses

    def test_uniq(self):
        a = [["cmd1", "arg1"], ["cmd1", "arg1"]]
        b = [["cmd1", "arg1"]]
        assert utils.uniq(a) == b
