import mock
import unittest

from lrbd import content
from lrbd import host


class ImagesTestCase(unittest.TestCase):

    def setUp(self):
        content.Common.config = {
            "pools": [
                {"pool": "rbd",
                 "gateways": [
                     {"host": "igw1", "tpg": [{"image": "archive"}]
                      }]
                 }]}

        class mock_Images(host.Images):
            def __init__(self):
                self.mounts = {}
        self.i = mock_Images()

    @mock.patch('lrbd.utils.popen')
    def test_map(self, mock_subproc_popen):
        self.i.map()
        assert mock_subproc_popen.called

    @mock.patch('lrbd.utils.popen')
    def test_map_with_existing(self, mock_subproc_popen):
        self.i.mounts["rbd:city"] = "/dev/rbd0"
        self.i.map()
        assert mock_subproc_popen.called

    @mock.patch('lrbd.utils.popen')
    def test_map_nothing(self, mock_subproc_popen):
        self.i.mounts["rbd:archive"] = "/dev/rbd0"
        self.i.map()
        assert not mock_subproc_popen.called

    @mock.patch('lrbd.utils.popen')
    def test_unmap(self, mock_subproc_popen):
        self.i.mounts["rbd:archive"] = "/dev/rbd0"
        self.i.unmap()
        assert mock_subproc_popen.called

    @mock.patch('lrbd.utils.popen')
    def test_unmap_nothing(self, mock_subproc_popen):
        self.i.unmap()
        assert not mock_subproc_popen.called
