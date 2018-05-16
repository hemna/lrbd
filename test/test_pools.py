
import unittest

from lrbd import content


class PoolsTestCase(unittest.TestCase):

    def setUp(self):
        self.p = content.Pools()
        self.p.add("swimming")

    def test_add(self):
        assert self.p.pools[0]['pool'] == "swimming"

    def test_append(self):
        data = {'gateways': []}
        self.p.append("swimming", data)
        self.p.display()
        assert self.p.pools[0]['pool'] == "swimming"
