
import argparse
import mock
import unittest

from lrbd import main as lrbd_main


class MainTestCase(unittest.TestCase):

    def setUp(self):
        self.args = argparse.Namespace()
        self.args.config = None
        self.args.ceph = "/etc/motd"
        self.args.host = None
        self.args.verbose = False
        self.args.debug = False
        self.args.name = "client.admin"
        self.args.pools = []
        self.args.wipe = False
        self.args.editor = None

    @mock.patch('lrbd.content.Configs.wipe')
    def test_main_wipe(self, mock_subproc_wipe):
        self.args.wipe = True
        lrbd_main.main(self.args)
        assert mock_subproc_wipe.called

    @mock.patch('lrbd.content.Configs.clear')
    def test_main_clear(self, mock_subproc_clear):
        self.args.wipe = False
        self.args.clear = True
        self.args.unmap = False
        lrbd_main.main(self.args)
        assert mock_subproc_clear.called

    @mock.patch('lrbd.content.Configs.clear')
    @mock.patch('lrbd.host.Images.__init__')
    @mock.patch('lrbd.host.Images.unmap')
    def test_main_clear_and_unmap(self, mock_clear, mock_init, mock_unmap):
        self.args.wipe = False
        self.args.clear = True
        self.args.unmap = True
        mock_init.return_value = None
        lrbd_main.main(self.args)
        assert (mock_clear.called and mock_unmap.called)

    @mock.patch('lrbd.host.Images')
    def test_main_unmap(self, mock_Images):
        self.args.wipe = False
        self.args.clear = False
        self.args.unmap = True
        lrbd_main.main(self.args)
        assert mock_Images.called

    @mock.patch('lrbd.content.Configs.wipe')
    @mock.patch('lrbd.content.Content')
    def test_main_file(self, mock_wipe, mock_Content):
        self.args.wipe = False
        self.args.clear = False
        self.args.unmap = False
        self.args.file = True
        lrbd_main.main(self.args)
        assert (mock_wipe.called and mock_Content.called)

    @mock.patch('lrbd.content.Content')
    def test_main_add(self, mock_Content):
        self.args.wipe = False
        self.args.clear = False
        self.args.unmap = False
        self.args.file = False
        self.args.add = True
        lrbd_main.main(self.args)
        assert mock_Content.called

    @mock.patch('lrbd.content.Configs')
    def test_main_output(self, mock_Configs):
        self.args.wipe = False
        self.args.clear = False
        self.args.unmap = False
        self.args.file = False
        self.args.add = False
        self.args.output = True
        lrbd_main.main(self.args)
        assert mock_Configs.called

    @mock.patch('lrbd.content.Configs')
    @mock.patch('lrbd.content.Content')
    def test_main_edit(self, mock_Configs, mock_Content):
        self.args.wipe = False
        self.args.clear = False
        self.args.unmap = False
        self.args.file = False
        self.args.add = False
        self.args.output = False
        self.args.edit = True
        self.args.editor = None
        self.args.migrate = False
        lrbd_main.main(self.args)
        assert (mock_Configs.called and mock_Content.called)

    @mock.patch('lrbd.content.Configs')
    def test_main_local(self, mock_Configs):
        self.args.wipe = False
        self.args.clear = False
        self.args.unmap = False
        self.args.file = False
        self.args.add = False
        self.args.output = False
        self.args.edit = False
        self.args.local = True
        self.args.migrate = False
        lrbd_main.main(self.args)
        assert mock_Configs.called

    @mock.patch('lrbd.content.Configs')
    @mock.patch('lrbd.host.Images')
    @mock.patch('lrbd.host.Backstores')
    @mock.patch('lrbd.host.BackstoreAttributes')
    @mock.patch('lrbd.host.Iscsi')
    @mock.patch('lrbd.host.TPGs')
    @mock.patch('lrbd.host.Luns')
    @mock.patch('lrbd.host.TPGattributes')
    @mock.patch('lrbd.host.Portals')
    @mock.patch('lrbd.host.Acls')
    @mock.patch('lrbd.host.Map')
    @mock.patch('lrbd.host.Auth')
    def test_main_default(self, mock_Configs, mock_Images, mock_Backstores,
                          mock_BackstoreAttributes,
                          mock_Iscsi, mock_TPGs, mock_Luns, mock_Portals,
                          mock_TPGattributes, mock_Acls, mock_Map, mock_Auth):
        self.args.wipe = False
        self.args.clear = False
        self.args.unmap = False
        self.args.file = False
        self.args.add = False
        self.args.output = False
        self.args.edit = False
        self.args.local = False
        self.args.migrate = False
        self.args.backstore = "iblock"
        lrbd_main.main(self.args)
        assert (mock_Configs.called and
                mock_Images.called and
                mock_Backstores.called and
                mock_BackstoreAttributes.called and
                mock_Iscsi.called and
                mock_TPGs.called and
                mock_Luns.called and
                mock_Portals.called and
                mock_TPGattributes.called and
                mock_Acls.called and
                mock_Map.called and
                mock_Auth.called)
