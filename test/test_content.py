
from nose import tools
import re
import tempfile
import unittest

from lrbd import content


class InitialContentsTestCase(unittest.TestCase):

    def setUp(self):
        content.Common.config = {"auth": [], "targets": [], "pools": []}
        self.initialcontents = content.InitialContents()

    def test_instructions(self):
        assert re.match(r'#.*\n', self.initialcontents._instructions())


class ContentTestCase(unittest.TestCase):

    def setUp(self):
        self.content = content.Content()

    def test_read(self):
        data = '''{ "pools": [ { "pool": "rbd",
                             "gateways": [ {
                                 "host": "igw1",
                                 "tpg": [ {
                                     "image": "archive",
                                     "initiator": "iqn"
                                 } ]
                             } ]
                         } ]
                   }'''
        with tempfile.NamedTemporaryFile(suffix=".tmp") as tmpfile:
            tmpfile.write(data)
            tmpfile.flush()
            self.content.read(tmpfile.name)
            assert self.content.submitted

    @tools.raises(IOError)
    def test_read_ioerror(self):
        self.content.read("missing_file")

    @tools.raises(RuntimeError)
    def test_read_runtimeerror(self):
        # Double comma
        data = '''{ "auth": [ { "host": "" } ], ,
                "pools": [ { "gateways": [ { "host": [], "tpg": [] } ] } ] }'''
        with tempfile.NamedTemporaryFile(suffix=".tmp") as tmpfile:
            tmpfile.write(data)
            tmpfile.flush()
            self.content.read(tmpfile.name)

    # test_validate works in test_read
    def test_validate_exception(self):
        assert self.content.validate("{,}") is False

    def test_verify_mandatory_keys_pools(self):
        try:
            self.content.verify_mandatory_keys("{}")
        except ValueError as e:
            assert re.match(r"Mandatory key 'pools' is missing", str(e))

    def test_verify_mandatory_keys_pool_contents(self):
        try:
            self.content.verify_mandatory_keys('{ "pools": [] }')
        except ValueError as e:
            assert re.match(r"pools have no entries", str(e))

    def test_verify_mandatory_keys_gateways(self):
        data = '{ "pools": [ { "pool": "" } ] }'
        try:
            self.content.verify_mandatory_keys(data)
        except ValueError as e:
            assert re.match(r"Mandatory key 'gateways' is missing", str(e))

    def test_verify_mandatory_keys_gateways_entries(self):
        data = '{ "pools": [ { "gateways": [] } ] }'
        try:
            self.content.verify_mandatory_keys(data)
        except ValueError as e:
            assert re.match(r"gateways have no entries", str(e))

    def test_verify_mandatory_keys_host_or_target(self):
        data = '{ "pools": [ { "gateways": [ { "tpg": [] } ] } ] }'
        try:
            self.content.verify_mandatory_keys(data)
        except ValueError as e:
            assert re.match(
                r"Mandatory key 'host' or 'target' is missing", str(e))

    def test_verify_mandatory_keys_tpg(self):
        data = '{ "pools": [ { "gateways": [ { "host": [] } ] } ] }'
        try:
            self.content.verify_mandatory_keys(data)
        except ValueError as e:
            assert re.match(r"Mandatory key 'tpg' is missing", str(e))

    def test_verify_mandatory_keys_auth(self):
        data = '''{ "auth": [ { "discovery": "" } ],
                "pools": [ { "gateways": [ { "host": [], "tpg": [] } ] } ] }'''
        try:
            self.content.verify_mandatory_keys(data)
        except ValueError as e:
            assert re.match(
                r"Mandatory key 'host' or 'target' is missing from auth",
                str(e))

    def test_remove_absent_entry_none(self):
        data = {"pools": [
            {"pool": "rbd", "gateways": [
                {"host": "igw1", "tpg": [{"image": "archive",
                                          "initiator": "iqn.xyz"}]}]}
        ]}
        self.content.current = data
        self.content.submitted = data

        class temp(content.Attributes):
            called = False

            def remove(self):
                self.called = True

        self.content.attr = temp(None)

        self.content._remove_absent_entry()
        assert not self.content.attr.called

    def test_remove_absent_entry(self):
        data = {"pools": [
            {"pool": "rbd", "gateways": [
                {"host": "igw1", "tpg": [
                    {"image": "archive", "initiator": "iqn.xyz"}]},
                {"host": "igw2", "tpg": [
                    {"image": "archive", "initiator": "iqn.wxy"}
                ]}
            ]}
        ]}
        self.content.current = data

        self.content.submitted = {"pools": [
            {"pool": "rbd", "gateways": [
                {"host": "igw1", "tpg": [
                    {"image": "archive", "initiator": "iqn.xyz"}
                ]}
            ]}
        ]}

        class temp(content.Attributes):
            called = False

            def remove(self, pool, key):
                self.called = True

        self.content.attr = temp(None)

        self.content._remove_absent_entry()
        assert self.content.attr.called
