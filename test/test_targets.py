
import unittest

from lrbd import content


class TargetsTestCase(unittest.TestCase):

    def setUp(self):
        self.t = content.Targets()
        self.data = [{"host": "igw1", "target": "iqn.xyz"}]

    def test_add(self):
        self.t.add(self.data)
        self.t.display()
        assert self.t.targets[0]['host'] == "igw1"

    def test_list(self):
        data = [{"hosts": [{"host": "igw1"}, {"host": "igw2"}],
                 "target": "iqn.xyz"}]
        self.t.add(data)
        content.Common.hostname = "igw1"
        targets = self.t.list()
        self.t.display()
        assert targets[0] == "iqn.xyz"

    def test_purge(self):
        self.t.add(self.data)
        content.Common.hostname = "igw2"
        self.t.purge()
        self.t.display()
        assert not self.t.targets
