
import mock
import tempfile
import unittest

from lrbd import content
from lrbd import host
from lrbd import runtime


class IscsiTestCase(unittest.TestCase):

    def test_iscsi_default(self):
        content.Common.config = {"targets": []}

        class mock_Iscsi(host.Iscsi):
            def _gen_wwn(self):
                pass

            def _assign_vendor(self):
                pass

        self.i = mock_Iscsi()
        assert self.i.cmds == [['targetcli', '/iscsi', 'create']]

    def test_iscsi_defined_target(self):
        content.Common.config = {"targets": [{"host": "igw1",
                                              "target": "iqn.xyz"}]}

        class mock_Iscsi(host.Iscsi):
            def _gen_wwn(self):
                pass

            def _assign_vendor(self):
                pass

        self.i = mock_Iscsi()
        assert self.i.cmds == [['targetcli', '/iscsi', 'create', 'iqn.xyz']]

    @mock.patch('lrbd.utils.popen')
    @mock.patch('glob.glob')
    def test_create_default(self, mock_subproc_popen, mock_subproc_glob):
        content.Common.config = {"targets": [{"host": "igw1",
                                              "target": "iqn.xyz"}]}
        mock_subproc_glob.return_value = ["/some/path/name"]

        class mock_Iscsi(host.Iscsi):
            def _gen_wwn(self):
                pass

            def _assign_vendor(self):
                pass

        self.i = mock_Iscsi()
        self.i.create()
        assert (mock_subproc_popen.called and
                content.Common.config['iqns'] == ["iqn.xyz"])

    @mock.patch('lrbd.utils.popen')
    def test_create(self, mock_subproc_popen):
        content.Common.config = {"targets": [{"host": "igw1",
                                              "target": "iqn.xyz"}]}

        class mock_Iscsi(host.Iscsi):
            def _gen_wwn(self):
                pass

            def _assign_vendor(self):
                pass

        self.i = mock_Iscsi()
        self.i.create()
        assert mock_subproc_popen.called

    @mock.patch('lrbd.runtime.Runtime.backstore')
    @mock.patch('lrbd.runtime.Runtime.core')
    @mock.patch('os.path.isfile')
    def test_assign_vendor(self, mock_backstore, mock_core, mock_isfile):

        runtime.Runtime.config['backstore'] = []
        content.Common.config = {"targets": [{"host": "igw1",
                                              "target": "iqn.xyz"}]}
        content.Common.config['pools'] = [
            {"pool": "rbd",
             "gateways": [
                     {"host": "igw1", "tpg": [
                         {"image": "archive"}
                     ]
                     }]
             }]

        with tempfile.NamedTemporaryFile(suffix=".tmp") as tmpfile:
            mock_backstore.return_value = "archive"
            mock_core.return_value = [tmpfile.name]
            mock_isfile.return_value = True

            class mock_Iscsi(host.Iscsi):
                def _arrange(self):
                    pass

            self.i = mock_Iscsi()
            self.i._assign_vendor()
            tmpfile.flush()
            contents = tmpfile.read().strip()
            assert contents == "SUSE"
