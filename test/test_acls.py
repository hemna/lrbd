
import mock
from nose import tools
import unittest

from lrbd import content
from lrbd import host
from lrbd import runtime


class AclsTestCase(unittest.TestCase):

    def setUp(self):
        content.Common.config['iqns'] = ["iqn.xyz"]
        content.Common.config['auth'] = [{"host": "igw1",
                                          "authentication": "acls"}]
        content.Common.config['portals'] = [{"name": "portal1",
                                             "addresses": ["172.16.1.16"]}]
        content.Common.config['pools'] = [
            {"pool": "rbd",
             "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive",
                          "initiator": "iqn.abc",
                          "portal": "portal1"}
                     ]}]}]

        runtime.Runtime.config['addresses'] = ["172.16.1.16"]
        runtime.Runtime.config['portals'] = {}
        runtime.Runtime.config['portals']["iqn.xyz"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"]["portal1"] = \
            "1"

    def test_acls(self):
        class mock_Acls(host.Acls):

            def _find(self):
                pass

            def _cmd(self, target, tpg, initiator):
                self.called = " ".join([target, str(tpg), initiator])

        self.a = mock_Acls()
        assert self.a.called == "iqn.xyz 1 iqn.abc"

    @tools.raises(AttributeError)
    def test_tpg(self):
        content.Common.config['auth'] = [{"host": "igw1",
                                          "authentication": "tpg"}]

        class mock_Acls(host.Acls):

            def _find(self):
                pass

            def _cmd(self, target, tpg, initiator):
                self.called = True

        self.a = mock_Acls()
        self.a.called

    @mock.patch('glob.glob')
    def test_find(self, mock_subproc_glob):
        mock_subproc_glob.return_value = ["/s/k/c/t/i/t/t_1/a/iqn.abc"]

        class mock_Acls(host.Acls):

            def _cmd(self, target, tpg, initiator):
                self.called = " ".join([target, str(tpg), initiator])

        self.a = mock_Acls()
        assert self.a.exists == {'iqn.xyz': {'1': ['iqn.abc']}}

    @mock.patch('glob.glob')
    def test_find_does_nothing(self, mock_subproc_glob):

        mock_subproc_glob.return_value = []

        class mock_Acls(host.Acls):

            def _cmd(self, target, tpg, initiator):
                self.called = " ".join([target, str(tpg), initiator])

        self.a = mock_Acls()
        assert not self.a.initiators

    def test_cmd(self):

        class mock_Acls(host.Acls):

            def _find(self):
                pass

        self.a = mock_Acls()
        assert self.a.cmds == [['targetcli', '/iscsi/iqn.xyz/tpg1/acls',
                                'create', 'iqn.abc']]

    @mock.patch('lrbd.utils.popen')
    def test_create(self, mock_subproc_popen):

        content.Common.config['iqns'] = ["iqn.xyz"]
        content.Common.config['portals'] = [{"name": "portal1",
                                             "addresses": ["172.16.1.16"]}]
        content.Common.config['pools'] = [
            {"pool": "rbd",
             "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive",
                          "initiator": "iqn.abc",
                          "portal": "portal1"}
                     ]}]}]

        runtime.Runtime.config['addresses'] = ["172.16.1.16"]
        runtime.Runtime.config['portals'] = {}
        runtime.Runtime.config['portals']["iqn.xyz"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"]["portal1"] = \
            "1"

        class mock_Acls(host.Acls):

            def _find(self):
                pass

            def _cmd(self, target, tpg, initiator):
                self.called = " ".join([target, str(tpg), initiator])

        self.a = mock_Acls()
        self.a.cmds = [["echo", "hello"]]
        self.a.create()
        assert mock_subproc_popen.called
