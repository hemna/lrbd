
import mock
from nose import tools
import unittest

from lrbd import content
from lrbd import host
from lrbd import runtime


class AuthTestCase(unittest.TestCase):

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

    @mock.patch('lrbd.content.Cluster')
    def test_auth_default(self, mock_cluster):
        content.Common.config['auth'] = [{"authentication": "none"}]

        class mock_Auth(host.Auth):

            def set_noauth(self):
                return("noauth")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        expected = ['noauth', 'discovery off']
        self.assertEqual(expected, self.a.cmds)

    def test_auth_none(self):
        content.Common.config['auth'] = [{"authentication": "none"}]

        class mock_Auth(host.Auth):

            def set_noauth(self):
                return("noauth")

            def select_discovery(self):
                return(["select_discovery"])

        self.a = mock_Auth()
        expected = ['noauth', 'select_discovery']
        self.assertEqual(expected, self.a.cmds)

    def test_auth_tpg(self):
        content.Common.config['auth'] = [{"authentication": "tpg"}]

        class mock_Auth(host.Auth):

            def select_tpg(self):
                return(["tpg"])

            def select_discovery(self):
                return(["select_discovery"])

        self.a = mock_Auth()
        expected = ['tpg', 'select_discovery']
        self.assertEqual(expected, self.a.cmds)

    def test_auth_tpg_identified(self):
        content.Common.config['auth'] = [{"authentication": "tpg+identified"}]

        class mock_Auth(host.Auth):

            def select_acls(self):
                return(["tpg+identified"])

            def select_discovery(self):
                return(["select_discovery"])

            def _generate_acls(self):
                pass

        self.a = mock_Auth()
        expected = ['tpg+identified', 'select_discovery']
        self.assertEqual(expected, self.a.cmds)

    def test_generate_acls(self):
        content.Common.config['auth'] = [
            {"authentication": "tpg+identified",
             "tpg": {"userid": "common1", "password": "pass1"}}
        ]
        content.Common.config['pools'] = []

        class mock_Auth(host.Auth):

            def select_acls(self):
                return(["tpg+identified"])

            def select_discovery(self):
                return(["select_discovery"])

            def _find_tpg_identified_initiators(self):
                return(["iqn.abc"])

        self.a = mock_Auth()
        expected = [
            {'initiator': 'iqn.abc', 'password': 'pass1', 'userid': 'common1'}
        ]
        self.assertEqual(expected, self.a.auth['acls'])

    def test_generate_acls_mutual(self):
        content.Common.config['auth'] = [
            {"authentication": "tpg+identified",
             "tpg": {"userid": "common1",
                     "password": "pass1",
                     "mutual": "enable",
                     "userid_mutual": "target1",
                     "password_mutual": "pass2"}}
        ]

        class mock_Auth(host.Auth):

            def select_acls(self):
                return(["tpg+identified"])

            def select_discovery(self):
                return(["select_discovery"])

            def _find_tpg_identified_initiators(self):
                return(["iqn.abc"])

        self.a = mock_Auth()
        expected = [
            {'userid_mutual': 'target1', 'initiator': 'iqn.abc',
             'userid': 'common1', 'mutual': 'enable',
             'password_mutual': 'pass2', 'password': 'pass1'}]
        self.assertEqual(expected, self.a.auth['acls'])

    def test_find_tpg_identified_initiators(self):
        content.Common.config['auth'] = [
            {"authentication": "tpg+identified",
             "host": "igw1", "tpg": {
                 "userid": "common1", "password": "pass1"}}
        ]

        content.Common.config['pools'] = [
            {"pool": "rbd",
             "gateways": [
                 {"host": "igw1", "tpg": [
                     {"image": "archive",
                      "initiator": "iqn.abc",
                      "portal": "portal1"}
                 ]}
             ]}
        ]

        class mock_Auth(host.Auth):

            def select_acls(self):
                return(["tpg+identified"])

            def select_discovery(self):
                return(["select_discovery"])

            def _generate_acls(self):
                pass

        self.a = mock_Auth()
        expected = ['iqn.abc']
        actual = self.a._find_tpg_identified_initiators()
        self.assertEqual(expected, actual)

    def test_auth_acls(self):
        content.Common.config['auth'] = [{"authentication": "acls"}]

        class mock_Auth(host.Auth):

            def select_acls(self):
                return(["acls"])

            def select_discovery(self):
                return(["select_discovery"])

        self.a = mock_Auth()
        expected = ['acls', 'select_discovery']
        self.assertEqual(expected, self.a.cmds)

    @tools.raises(ValueError)
    def test_auth_invalid(self):
        content.Common.config['auth'] = [{"authentication": "invalid"}]

        self.a = host.Auth()

    def test_select_discovery_default(self):
        content.Common.config['auth'] = [{"authentication": "none"}]

        class mock_Auth(host.Auth):

            def set_noauth(self):
                return("noauth")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        expected = ['noauth', 'discovery off']
        self.assertEquals(expected, self.a.cmds)

    def test_select_discovery_off(self):
        content.Common.config['auth'] = [{"authentication": "none"}]

        class mock_Auth(host.Auth):

            def set_noauth(self):
                return("noauth")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        expected = ['noauth', 'discovery off']
        self.assertEqual(expected, self.a.cmds)

    def test_select_discovery_off_explicit(self):
        content.Common.config['auth'] = [{"authentication": "none",
                                          "discovery": {"auth": "disable"}}]

        class mock_Auth(host.Auth):

            def set_noauth(self):
                return("noauth")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        expected = ['noauth', 'discovery off']
        self.assertEquals(expected, self.a.cmds)

    def test_select_discovery_on(self):
        content.Common.config['auth'] = [{"authentication": "none",
                                          "discovery": {"auth": "enable"}}]

        class mock_Auth(host.Auth):

            def set_noauth(self):
                return("noauth")

            def set_discovery(self):
                return("discovery on")

        self.a = mock_Auth()
        expected = ['noauth', 'discovery on']
        self.assertEquals(expected, self.a.cmds)

    def test_select_discovery_on_mutual_off(self):
        content.Common.config['auth'] = [{"authentication": "none",
                                          "discovery": {"auth": "enable",
                                                        "mutual": "disable"}}]

        class mock_Auth(host.Auth):

            def set_noauth(self):
                return("noauth")

            def set_discovery(self):
                return("discovery on")

        self.a = mock_Auth()
        expected = ['noauth', 'discovery on']
        self.assertEquals(expected, self.a.cmds)

    def test_select_discovery_on_mutual_on(self):
        content.Common.config['auth'] = [{"authentication": "none",
                                          "discovery": {"auth": "enable",
                                                        "mutual": "enable"}}]

        class mock_Auth(host.Auth):

            def set_noauth(self):
                return("noauth")

            def set_discovery_mutual(self):
                return("discovery_mutual on")

        self.a = mock_Auth()
        expected = ['noauth', 'discovery_mutual on']
        self.assertEquals(expected, self.a.cmds)

    def test_select_tpg(self):
        content.Common.config['auth'] = [{"authentication": "tpg",
                                          "tpg": {}}]

        class mock_Auth(host.Auth):

            def set_tpg(self):
                return("tpg")

            def set_tpg_mode(self):
                return("tpg mode")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        expected = ['tpg', 'tpg mode', 'discovery off']
        self.assertEqual(expected, self.a.cmds)

    def test_select_tpg_mutual_off(self):
        content.Common.config['auth'] = [{"authentication": "tpg",
                                          "tpg": {"mutual": "disable"}}]

        class mock_Auth(host.Auth):

            def set_tpg(self):
                return("tpg")

            def set_tpg_mode(self):
                return("tpg mode")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        expected = ['tpg', 'tpg mode', 'discovery off']
        self.assertEqual(expected, self.a.cmds)

    def test_select_tpg_mutual_on(self):
        content.Common.config['auth'] = [{"authentication": "tpg",
                                          "tpg": {"mutual": "enable"}}]

        class mock_Auth(host.Auth):

            def set_tpg_mutual(self):
                return("tpg mutual")

            def set_tpg_mode(self):
                return("tpg mode")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        expected = ['tpg mutual', 'tpg mode', 'discovery off']
        self.assertEqual(expected, self.a.cmds)

    def test_select_acls_default(self):
        content.Common.config['auth'] = [{"authentication": "acls",
                                          "acls": {}}]

        class mock_Auth(host.Auth):

            def set_acls(self):
                return("acls")

            def set_acls_mode(self):
                return("acls mode")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        expected = ['acls mode', 'discovery off']
        self.assertEqual(expected, self.a.cmds)

    def test_select_acls(self):
        content.Common.config['auth'] = [{"authentication": "acls",
                                          "acls": {"initiator": "iqn.abc"}}]

        class mock_Auth(host.Auth):

            def set_acls(self):
                return("acls")

            def set_acls_mode(self):
                return("acls mode")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        expected = ['acls', 'acls mode', 'discovery off']
        self.assertEqual(expected, self.a.cmds)

    def test_select_acls_mutual_off(self):
        content.Common.config['auth'] = [{"authentication": "acls",
                                          "acls": [{"initiator": "iqn.abc",
                                                    "mutual": "disable"}]}]

        class mock_Auth(host.Auth):

            def set_acls(self):
                return("acls")

            def set_acls_mode(self):
                return("acls mode")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        expected = ['acls', 'acls mode', 'discovery off']
        self.assertEqual(expected, self.a.cmds)

    def test_select_acls_mutual_on(self):
        content.Common.config['auth'] = [{"authentication": "acls",
                                          "acls": [{"initiator": "iqn.abc",
                                                    "mutual": "enable"}]}]

        class mock_Auth(host.Auth):

            def set_acls_mutual(self):
                return("acls mutual")

            def set_acls_mode(self):
                return("acls mode")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        expected = ['acls mutual', 'acls mode', 'discovery off']
        self.assertEqual(expected, self.a.cmds)

    @mock.patch('lrbd.utils.popen')
    def test_create(self, mock_subproc_popen):
        content.Common.config['auth'] = [{"authentication": "none"}]

        class mock_Auth(host.Auth):

            def set_noauth(self):
                return("noauth")

            def set_discovery_off(self):
                return("discovery off")

        self.a = mock_Auth()
        self.a.create()
        assert mock_subproc_popen.called
