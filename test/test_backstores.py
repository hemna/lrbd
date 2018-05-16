
import mock
import unittest

from lrbd import content
from lrbd import host
from lrbd import runtime


class BackstoresTestCase(unittest.TestCase):

    @mock.patch('lrbd.content.Cluster')
    @mock.patch('lrbd.utils.popen')
    def setUp(self, mock_cluster, mock_popen):
        runtime.Runtime.config = {}
        runtime.Runtime.config['addresses'] = ["172.16.1.16"]
        runtime.Runtime.config['portals'] = {}
        runtime.Runtime.config['portals']["iqn.xyz"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"] = {}
        runtime.Runtime.config['portals']["iqn.xyz"]["archive"]["portal1"] = \
            "1"
        content.Common.config['iqns'] = ['iqn.xyz']
        content.Common.config['pools'] = []

    def test_backstores_default(self):
        class mock_Backstores(host.Backstores):

            def _load_modules(self):
                pass

            def _rbd(self):
                pass

            def _iblock(self):
                pass

        self.b = mock_Backstores(None)
        assert runtime.Runtime.config['backstore'] == "rbd"

    def test_backstores_iblock(self):
        class mock_Backstores(host.Backstores):

            def _load_modules(self):
                pass

            def _rbd(self):
                pass

            def _iblock(self):
                pass

        self.b = mock_Backstores("iblock")
        assert runtime.Runtime.config['backstore'] == "iblock"

    def test_backstores_rbd(self):
        class mock_Backstores(host.Backstores):

            def _load_modules(self):
                pass

            def _rbd(self):
                pass

            def _iblock(self):
                pass

        self.b = mock_Backstores("rbd")
        assert runtime.Runtime.config['backstore'] == "rbd"

    def test_iblock(self):

        content.Common.config = {
            "pools": [
                {"pool": "rbd",
                 "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive"}
                     ]
                     }]
                 }]}

        self.b = host.Backstores("iblock")
        assert self.b.cmds == [['targetcli', '/backstores/iblock',
                                'create', 'name=rbd-archive',
                                'dev=/dev/rbd/rbd/archive']]

    def test_iblock_simple(self):

        content.Common.config = {
            "pools": [
                {"pool": "rbd",
                 "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive", "rbd_name": "simple"}
                     ]
                     }]
                 }]}

        self.b = host.Backstores("iblock")
        assert self.b.cmds == [['targetcli', '/backstores/iblock',
                                'create', 'name=archive',
                                'dev=/dev/rbd/rbd/archive']]

    @mock.patch('glob.glob')
    def test_iblock_does_nothing(self, mock_subproc_glob):
        content.Common.config = {
            "pools": [
                {"pool": "rbd",
                 "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive"}
                     ]
                     }]
                 }]}

        mock_subproc_glob.return_value = "globbed/path/name"
        self.b = host.Backstores("iblock")
        assert not self.b.cmds

    @mock.patch('glob.glob')
    def test_detect_default(self, mock_subproc_glob):
        content.Common.config = {
            "pools": [
                {"pool": "rbd",
                 "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive"}
                     ]
                     }]
                 }]}

        class mock_Backstores(host.Backstores):
            def _load_modules(self):
                pass

        mock_subproc_glob.return_value = []
        self.b = mock_Backstores(None)

        assert self.b.selected == "rbd"

    @mock.patch('glob.glob')
    def test_detect_existing(self, mock_subproc_glob):
        content.Common.config = {
            "pools": [
                {"pool": "rbd",
                 "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive"}
                     ]
                     }]
                 }]}

        mock_subproc_glob.return_value = ["/s/k/c/t/c/BACKSTORE_0/archive"]
        self.b = host.Backstores(None)
        assert self.b.selected == "BACKSTORE"

    def test_rbd(self):

        content.Common.config = {
            "pools": [
                {"pool": "rbd",
                 "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive"}
                     ]
                     }]
                 }]}

        class mock_Backstores(host.Backstores):
            def _load_modules(self):
                pass

        self.b = mock_Backstores("rbd")
        assert self.b.cmds == [['targetcli', '/backstores/rbd',
                                'create', 'name=rbd-archive',
                                'dev=/dev/rbd/rbd/archive']]

    def test_rbd_simple(self):

        content.Common.config = {
            "pools": [
                {"pool": "rbd",
                 "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive", "rbd_name": "simple"}
                     ]
                     }]
                 }]}

        class mock_Backstores(host.Backstores):
            def _load_modules(self):
                pass

        self.b = mock_Backstores("rbd")
        assert self.b.cmds == [['targetcli', '/backstores/rbd',
                                'create', 'name=archive',
                                'dev=/dev/rbd/rbd/archive']]

    @mock.patch('glob.glob')
    def test_rbd_does_nothing(self, mock_subproc_glob):
        content.Common.config = {
            "pools": [
                {"pool": "rbd",
                 "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive"}
                     ]
                     }]
                 }]}

        class mock_Backstores(host.Backstores):
            def _load_modules(self):
                pass

        mock_subproc_glob.return_value = "globbed/path/name"
        self.b = mock_Backstores("rbd")
        assert not self.b.cmds

    @mock.patch('lrbd.utils.popen')
    def test_create(self, mock_subproc_popen):
        content.Common.config = {
            "pools": [
                {"pool": "rbd",
                 "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive"}
                     ]
                     }]
                 }]}

        self.b = host.Backstores("iblock")
        self.b.create()
        assert mock_subproc_popen.called
