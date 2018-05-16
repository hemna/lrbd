import mock
from nose import tools
import unittest

from lrbd import content
from lrbd import host
from lrbd import runtime


class PortalsTestCase(unittest.TestCase):

    def setUp(self):
        content.Common.config['iqns'] = ["iqn.xyz"]
        content.Common.config['portals'] = [{"name": "portal1",
                                             "addresses": ["172.16.1.16"]}]
        runtime.Runtime.config = {}
        runtime.Runtime.config['addresses'] = ["172.16.1.16"]
        runtime.Runtime.config['portals'] = {}
        runtime.Runtime.config['portals']["iqn.xyz"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"]["portal1"] = \
            "1"

    def test_portal_default(self):
        content.Common.config['iqns'] = ["iqn.xyz"]
        content.Common.config['portals'] = []

        class mock_Portals(host.Portals):

            called = False

            def _cmd(self, target, tpg, address):
                self.called = True

        self.pt = mock_Portals()
        assert self.pt.called

    def test_portal(self):

        class mock_Portals(host.Portals):

            def _entries(self):
                yield("iqn.xyz", "archive", "portal1",
                      content.Common.config['portals'][0])

            def _cmd(self, target, tpg, address):
                self.called = " ".join([target, tpg, address])

        self.pt = mock_Portals()
        assert self.pt.called == "iqn.xyz 1 172.16.1.16"

    def test_portal_remote(self):
        content.Common.config['portals'] = [{"name": "portal2",
                                             "addresses": ["172.16.1.17"]}]
        runtime.Runtime.config = {}
        runtime.Runtime.config['portals'] = {}
        runtime.Runtime.config['portals']["iqn.xyz"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"]["portal2"] = \
            "2"

        class mock_Portals(host.Portals):

            def _entries(self):
                yield("iqn.xyz", "archive", "portal2",
                      content.Common.config['portals'][0])

            def _cmd(self, target, tpg, address):
                self.called = " ".join([target, tpg, address])

        self.pt = mock_Portals()
        assert self.pt.called == "iqn.xyz 2 172.16.1.17"

    def test_entries(self):

        class mock_Portals(host.Portals):

            def _cmd(self, target, tpg, address):
                self.called = " ".join([target, tpg, address])

        self.pt = mock_Portals()
        assert self.pt.called == "iqn.xyz 1 172.16.1.16"

    @tools.raises(ValueError)
    def test_entries_exception(self):
        del content.Common.config
        content.Common.config = {}
        content.Common.config['iqns'] = ["iqn.xyz"]
        content.Common.config['portals'] = [{"name": "portal99"}]

        class mock_Portals(host.Portals):

            def _cmd(self, target, tpg, address):
                self.called = " ".join([target, tpg, address])

        self.pt = mock_Portals()

    @mock.patch('glob.glob')
    def test_portal_remote_does_nothing(self, mock_subproc_glob):
        runtime.Runtime.config['addresses'] = ["172.16.1.17"]

        mock_subproc_glob.return_value = ["/some/path"]

        self.pt = host.Portals()
        assert self.pt.cmds == []

    @mock.patch('lrbd.utils.popen')
    def test_create(self, mock_subproc_popen):
        runtime.Runtime.config['addresses'] = ["172.16.1.17"]
        runtime.Runtime.config['portals'] = {}
        runtime.Runtime.config['portals']["iqn.xyz"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"]["portal1"] = \
            "1"

        mock_subproc_popen.return_value = []

        self.pt = host.Portals()
        self.pt.create()
        assert mock_subproc_popen.called
