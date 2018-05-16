
from __future__ import print_function
from collections import OrderedDict
import json
import logging
import os
import pprint
import rados
import socket
from subprocess import call
import tempfile

from lrbd import utils


def entries():
    """Generator yielding pool, gateway and tpg entries """
    for pentry in Common.config['pools']:
        if 'gateways' in pentry:
            for gentry in pentry['gateways']:
                for entry in gentry['tpg']:
                    yield (pentry, gentry, entry)


class Common(object):
    """Sharing common static configurations.  """
    config = OrderedDict()

    config_name = ""
    ceph_conf = ""
    hostname = ""
    pool_list = []
    client_name = ""

    @staticmethod
    def assign(sections):
        """Map sections keys into Common.config """
        Common.config['auth'] = \
            sections["authentications"].authentications
        Common.config['targets'] = sections["targets"].targets
        Common.config['portals'] = sections["portals"].portals
        Common.config['pools'] = sections["pools"].pools


class Configs(object):
    """Ceph Config.

    Read the configuration from Ceph for both global and host only
    configurations.  Merges pools, targets and authentications into
    larger structures.  Assigns to Common.* for sharing with other
    classes.
    """

    def __init__(self, config_name, ceph_conf, hostname, client_name,
                 pool_list):
        """Set initial overrides and assign to Common configuration

            config_name - a string for the name of the configuration object
                          in Ceph
            ceph_conf - an alternative Ceph configuration file
            hostname - specify an alternative gateway host
            client_name - specify a Ceph client name for authentication
            pool_list - specify a pool list
        """
        self.config_name = config_name if config_name else "lrbd.conf"
        self.ceph_conf = ceph_conf if ceph_conf else "/etc/ceph/ceph.conf"

        if not os.path.isfile(self.ceph_conf):
            raise IOError("{} does not exist".format(self.ceph_conf))

        self.client_name = client_name if client_name else "client.admin"
        self.hostname = [hostname] if hostname else [socket.gethostname(),
                                                     socket.getfqdn()]
        self.pool_list = pool_list if pool_list else None

        Common.config_name = self.config_name
        Common.ceph_conf = self.ceph_conf
        Common.hostname = self.hostname
        Common.client_name = self.client_name
        Common.pool_list = self.pool_list

    def retrieve(self, conn, sections, gateways):
        """Get configs.

        Scan all configuration objects and build a structure containing
        all gateway hosts.  Merge pools, auth, portals and targets into
        Common.config
        """
        with conn as cluster:
            if self.pool_list is None:
                self.pool_list = cluster.list_pools()
            for pool in self.pool_list:
                pool_id = cluster.pool_lookup(pool)
                tier_id = cluster.get_pool_base_tier(pool_id)
                if (pool_id != tier_id):
                    logging.info("Skipping tier cache {}".format(pool))
                    continue
                conn = Ioctx(cluster, pool)
                with conn as ioctx:
                    if self._config_missing(ioctx, self.config_name, pool):
                        continue
                    sections["pools"].add(pool)
                    sections["targets"].add(
                        self._get_optional(ioctx, self.config_name, 'targets'))
                    sections["portals"].add(
                        self._get_optional(ioctx, self.config_name, 'portals'))

                    gateways.find_portals()
                    attrs = ioctx.get_xattrs(self.config_name)
                    for key, value in attrs:
                        if key == "targets" or key == "portals":
                            continue
                        elif key[0] == "_":
                            sections["authentications"].add(
                                json.loads(value,
                                           object_pairs_hook=OrderedDict))
                        else:
                            gateways.add(key, value, self.hostname)
        gateways.purge()
        Common.assign(sections)

    def _config_missing(self, ioctx, config_name, pool):
        """Check for configuration object

            ioctx - existing pool connection
            config_name - name of the configuration object
            pool - name of pool
        """
        try:
            ioctx.stat(config_name)  # Check for object
        except rados.ObjectNotFound:
            # No configuration for pool, skipping
            logging.info("No configuration object {} in pool {}".
                         format(self.config_name, pool))
            return True
        return False

    def _get_optional(self, ioctx, config_name, attr):
        """Load value of specified attribute, may not exist

            ioctx - existing pool connection
            config_name - name of the configuration object
            attr - key desired (e.g. 'targets' or 'portals')
        """
        try:
            # Seems to cause an issue for some with several dozen targets,
            # use a for loop to return the same value
            # return json.loads(ioctx.get_xattr(config_name, attr),
            #        object_pairs_hook=OrderedDict)
            for k, v in ioctx.get_xattrs(config_name):
                logging.debug("_get_optional: key {} value {}".format(k, v))
                if k == attr:
                    return json.loads(v, object_pairs_hook=OrderedDict)
        except rados.NoData:
            pass

    def display(self):
        """JSON dump of structure to user.

        Keys are sorted which makes the format obnoxious when reviewing.

        TODO: custom JSON output with keys sorted by significance.
        """
        print(json.dumps(Common.config, indent=4))

    def wipe(self, conn):
        """Remove configuration objects from all pools """
        # conn = Cluster()
        with conn as cluster:
            if self.pool_list is None:
                self.pool_list = cluster.list_pools()
            for pool in self.pool_list:
                conn = Ioctx(cluster, pool)
                with conn as ioctx:
                    try:
                        ioctx.remove_object(self.config_name)
                        logging.debug("Removing {} from pool {}".
                                      format(self.config_name, pool))
                    except rados.ObjectNotFound:
                        logging.info("No object {} to remove from pool {}".
                                     format(self.config_name, pool))

    def clear(self):
        """Reset any targetcli configuration.

        Note: the clearconfig option is missing from the current targetcli
        which would remove the additional dependencies
        """
        cmds = [["/usr/sbin/tcm_fabric", "--unloadall"],
                ["/usr/sbin/lio_node", "--unload"],
                ["/usr/sbin/tcm_node", "--unload"]]
        for cmd in cmds:
            utils.popen(cmd)

    def migrate(self, version):
        """Migrate.

        Defaults have changed.  Add keywords to relevant sections to keep
        previous default behavior.
        """
        if version == "1.0":
            for entry in Common.config['targets']:
                if 'target' in entry:
                    entry['wwn_generate'] = "original"

            for pentry, gentry, entry in entries():
                if 'image' in entry:
                    entry['rbd_name'] = "simple"
        else:
            raise RuntimeError(
                "Migration of version {} unsupported\nSupported versions: 1.0".
                format(version))


class InitialContents(object):
    """Provides the initial contents for the editor """

    def __init__(self):
        if (not Common.config['auth'] and
                not Common.config['targets'] and not Common.config['pools']):
            self.text = self._instructions()
        else:
            self.text = json.dumps(Common.config, indent=2)

    def _instructions(self):
        """Initial instructions when no configuration exists """
        return utils.lstrip_spaces("""#
            #
            # lrbd stores an iSCSI configuration in Ceph and applies the
            # configuration to a host acting as a gateway between Ceph and an
            # initiator (i.e. iSCSI client)
            #
            # Since no configuration exists, the simplest example is provided
            # below.  Replace 'rbd', 'igw1', 'archive' and
            # 'iqn.1996-04.de.suse:01:abcdefghijkl' with your pool, host,
            # rbd image name and initator iqn.
            #
            # Alternatively, check the samples/ subdirectory.  Select the most
            # suitable configuration and customize.  Apply your configuration
            # with 'lrbd -f <filename>'.  For additional options, run 'lrbd -h'
            #
              {
                "pools": [
                  { "pool": "rbd",
                    "gateways": [
                      { "host": "igw1",
                        "tpg": [
                          { "image": "archive",
                            "initiator": "iqn.1996-04.de.suse:01:abcdefghijkl"
                          }
                        ]
                      }
                    ]
                  }
                ]
              }


            #\n""")

    def text(self):
        return self.text


class Content(object):
    """Content for operations.

    Contains operations for reading, editing and saving the configuration to
    Ceph.
    """

    def __init__(self):
        """Constructor.

        The variable self.current holds the JSON structure of the existing
        configuration.
        """
        self.current = {}
        self.initial_content = ""
        self.submitted = ""

    def edit(self, editor):
        """Edit the config.

        Edit the global configuration in a text editor.  Submitted changes
        are validated.  Errors are displayed after an edit session allowing
        a user to start another edit session or interrupt the program.

            editor - specify another editor, defaults to vim
        """
        self.current = Common.config
        program = editor if editor else os.environ.get('EDITOR',
                                                       '/usr/bin/vim')
        self.initial_content = InitialContents()

        with tempfile.NamedTemporaryFile(suffix=".tmp", mode='w') as tmpfile:
            tmpfile.write(self.initial_content.text)
            tmpfile.flush()

            valid = False
            while not valid:
                call([program, tmpfile.name])
                valid, self.submitted = self._check(tmpfile.name)
                if not valid:
                    try:
                        raw_input("Press enter to edit or Ctrl-C to quit ")
                    except KeyboardInterrupt:
                        raise SystemExit("\nBye")

    def read(self, filename):
        """read the config.

        The counterpart to using an editor, this method reads a file directly
        and runs the same validation.

            file - a text configuration file
        """
        if not os.path.isfile(filename):
            raise IOError("file '{}' does not exist".format(filename))
        valid, self.submitted = self._check(filename)
        if not valid:
            raise RuntimeError("file {} failed validation".format(filename))

    def _check(self, filename):
        """Check.

        Returns a tuple of whether the file provided is valid and a json
        structure of its contents

            filename - a string
        """
        submitted = utils.strip_comments(open(filename).read())
        valid = (self.validate(submitted) and
                 self.verify_mandatory_keys(submitted))
        if valid:
            text = json.loads(submitted, object_pairs_hook=OrderedDict)
        else:
            text = ""
        return(valid, text)

    def validate(self, text):
        """Validate.

        JSON format is finicky about trailing commas and such.  Print
        the errors to stdout.

            text - a string of the entire configuration
        """
        try:
            json.loads(text)
        except ValueError as error:
            logging.error(error)
            return False
        return True

    def verify_mandatory_keys(self, text):
        """Checks mandatory.

        Checks for dictionary keys related to the global data structure.

            text - a string of the entire configuration
        """
        content = json.loads(text)
        if 'pools' not in content:
            raise ValueError("Mandatory key 'pools' is missing")
        if not content['pools']:
            raise ValueError("pools have no entries")
        if 'gateways' not in content['pools'][0]:
            raise ValueError("Mandatory key 'gateways' is missing")
        if not content['pools'][0]['gateways']:
            raise ValueError("gateways have no entries")
        if not ('host' in content['pools'][0]['gateways'][0] or
                'target' in content['pools'][0]['gateways'][0]):
            raise ValueError("Mandatory key 'host' or 'target' is missing")
        if 'tpg' not in content['pools'][0]['gateways'][0]:
            raise ValueError("Mandatory key 'tpg' is missing")

        # Authentication section is optional, but keys are required
        # when present
        if 'auth' in content:
            for entry in content['auth']:
                if not ('host' in entry or 'target' in entry):
                    raise ValueError(
                        "Mandatory key 'host' or 'target' is missing from "
                        "auth")
        return True

    def save(self, conn):
        """Write config.

        Write the configuration to Ceph.  Remove any entries that were deleted
        from the submission.  Data is subdivided for simpler host retrieval.

        Stores the following attributes:
            targets - static iqn for each gateway host.  Stored on each
                      configuration object in every pool if it exists.
            portals - named groups of network addresses
            _<host> - authentication information for gateway host
            _<target> - authentication information for target
            <host>  - pool information for gateway host
            <target>  - pool information for redundant target
        """
        if self.submitted != self.current:
            logging.debug("Saving...")
            with conn as cluster:
                self.attr = Attributes(cluster)
                self._remove_deleted()
                self._update_submitted()

    def _remove_deleted(self):
        """Remove no longer needed extended attributes """
        self._remove_absent_entry()
        self._remove_absent_auth()
        self._remove_absent_auth_entry()

    def _update_submitted(self):
        """Create or update extended attributes for each section """
        for pool in self.submitted['pools']:
            if 'gateways' in pool:
                for gateway in pool['gateways']:
                    self._write_host(pool, gateway)
                    self._write_target(pool, gateway)
            if 'auth' in self.submitted:
                self._write_auth(pool)
            if 'targets' in self.submitted:
                self._write_targets(pool)
            if 'portals' in self.submitted:
                self._write_portals(pool)

    def _remove_absent_entry(self):
        """Remove host.

        Remove host or target entries that have been deleted from the
        submitted configuration
        """
        logging.debug("Removing deleted entries")
        hosts = {}
        if 'pools' in self.current and self.current['pools']:
            for pool in self.current['pools']:
                hosts[pool['pool']] = []
                self._add_current_gateways(pool, hosts)
            for pool in self.submitted['pools']:
                self._subtract_submitted_gateways(pool, hosts)
                self._remove_difference(pool, hosts)

    def _add_current_gateways(self, pool, hosts):
        """Adds gateways from current configuration """
        if 'gateways' in pool:
            for gateway in pool['gateways']:
                if 'host' in gateway:
                    hosts[pool['pool']].append(gateway['host'])
                if 'target' in gateway:
                    hosts[pool['pool']].append(gateway['target'])

    def _subtract_submitted_gateways(self, pool, hosts):
        """Subtracts gateways in submitted configuration """
        if 'gateways' in pool:
            for gateway in pool['gateways']:
                if ('host' in gateway and
                        gateway['host'] in hosts[pool['pool']]):
                    hosts[pool['pool']].remove(gateway['host'])
                if ('target' in gateway and
                        gateway['target'] in hosts[pool['pool']]):
                    hosts[pool['pool']].remove(gateway['target'])

    def _remove_difference(self, pool, hosts):
        """Remove diffs.

        Removes the differences between the current and submitted
        """
        for host in hosts[pool['pool']]:
            self.attr.remove(str(pool['pool']), str(host))
            logging.debug("Removing host {} from pool {}".format(host, pool))

    def _remove_absent_auth(self):
        """Remove auth.

        Remove auth section that has been deleted from the submitted
        configuration
        """
        if ('auth' in self.current and self.current['auth'] and
                'auth' not in self.submitted):
            for pool in self.submitted['pools']:
                self.attr.remove_auth(str(pool['pool']))

    def _remove_absent_auth_entry(self):
        """Remove entry from the auth section """
        if ('auth' in self.current and self.current['auth'] and
                'auth' in self.submitted and self.submitted['auth']):
            for old in self.current['auth']:
                found = False
                for key in ['host', 'target']:
                    if key in old:
                        for new in self.submitted['auth']:
                            if key in new:
                                if old[key] == new[key]:
                                    found = True
                        if not found:
                            for pool in self.submitted['pools']:
                                logging.debug("removing {} from {}".
                                              format(old[key], pool['pool']))
                                self.attr.remove_auth(str(pool['pool']),
                                                      old[key])

    def _write_host(self, pool, gateway):
        """Write a host entry """
        if 'host' in gateway:
            self.attr.write(str(pool['pool']),
                            str(gateway['host']), json.dumps(gateway))

    def _write_target(self, pool, gateway):
        """Write a target entry """
        if 'target' in gateway:
            self.attr.write(str(pool['pool']),
                            str(gateway['target']), json.dumps(gateway))

    def _write_auth(self, pool):
        """Write authentication entry for host or target """
        for entry in self.submitted['auth']:
            if 'host' in entry:
                self.attr.write(str(pool['pool']),
                                str('_' + entry['host']), json.dumps(entry))
            elif 'target' in entry:
                self.attr.write(str(pool['pool']),
                                str('_' + entry['target']), json.dumps(entry))
            else:
                raise ValueError(
                    "auth entry must contain either 'host' or 'target'")

    def _write_targets(self, pool):
        """Write targets section """
        self.attr.write(str(pool['pool']),
                        str('targets'), json.dumps(self.submitted['targets']))

    def _write_portals(self, pool):
        """Write portals section """
        self.attr.write(str(pool['pool']),
                        str('portals'), json.dumps(self.submitted['portals']))


class Cluster(object):
    """Support 'with' for Rados connections """

    def __init__(self):
        """Capture pool name """
        self.cluster = None

    def __enter__(self):
        """Connect to Ceph, return connection """
        self.cluster = rados.Rados(conffile=Common.ceph_conf,
                                   name=Common.client_name)
        try:
            self.cluster.connect()
        except rados.ObjectNotFound:
            raise IOError("check for missing keyring")
        return self.cluster

    def __exit__(self, exc_ty, exc_val, tb):
        """Close connection """
        self.cluster.shutdown()


class Ioctx(object):
    """Support 'with' for pool connections """

    def __init__(self, cluster, pool):
        """Capture pool name """
        self.cluster = cluster
        self.ioctx = None
        self.pool = pool

    def __enter__(self):
        """Connect to Ceph, open pool, return connection """
        try:
            self.ioctx = self.cluster.open_ioctx(self.pool)
        except rados.ObjectNotFound:
            raise RuntimeError("pool '{}' does not exist".format(self.pool))
        return self.ioctx

    def __exit__(self, exc_ty, exc_val, tb):
        """Close pool """
        self.ioctx.close()


class Attributes(object):
    """Methods for updating and removing extended attributes within Ceph.  """

    def __init__(self, cluster):
        self.cluster = cluster

    def write(self, pool, key, attrs):
        """Write an empty object and set an extended attribute

            pool - a string, name of Ceph pool
            key - a string, name of gateway host or target
            attrs - a string, json format
        """
        conn = Ioctx(self.cluster, pool)
        with conn as ioctx:
            ioctx.write_full(Common.config_name, bytes("", 'utf-8'))
            ioctx.set_xattr(Common.config_name, key,
                            bytes(attrs, 'utf-8'))
            logging.debug("Writing {} to pool {}".format(key, pool))

    def remove(self, pool, attr):
        """Remove a specified attribute.

        This is necessary when a host has been removed from the
        list of gateways

            pool - a string, name of Ceph pool
            attr - a string, name of gateway host
        """
        conn = Ioctx(self.cluster, pool)
        with conn as ioctx:
            ioctx.rm_xattr(Common.config_name, attr)
            logging.debug("Removing {} from pool {}".format(attr, pool))

    def remove_auth(self, pool, host=""):
        """Remove authentication attributes for a pool

            pool - a string, name of Ceph pool
            host - a string, specific host to remove. Empty string matches all.
        """
        conn = Ioctx(self.cluster, pool)
        with conn as ioctx:
            for key, value in ioctx.get_xattrs(Common.config_name):
                if (not host and key[0] == "_") or (key == ("_" + host)):
                    ioctx.rm_xattr(Common.config_name, key)
                    logging.debug("Removing {} from pool {}".format(key, pool))


#################################################################
class Pools(object):
    """Manage Pools.

    Manages the entire structure of pools, gateways, tpg and initiators.
    All hosts are included.
    """

    def __init__(self):
        """A list of pools.  Data structure is label : value throughout.  """
        self.pools = []

    def add(self, item):
        """Creates another pool entry

            item - dict (e.g. "pool": "swimming")
        """
        self.pools.append(OrderedDict())
        self.pools[-1]['pool'] = item

    def append(self, key, item):
        """Append another.

        Adds another JSON structure to 'key' in the same named pool above.

            key - a string such as "gateways"
            item - JSON structure of host, tpg and portals
        """
        if key not in self.pools[-1]:
            self.pools[-1][key] = []
        self.pools[-1][key].append(item)

    def display(self):
        """Useful for debugging """
        pprint.pprint(self.pools)


class PortalSection(object):
    """Managers the portals.

    Manages the portal section of the extended attributes (i.e. all data stored
    under portals).
    """

    def __init__(self):
        """List of portals.

        List of portals, entries are name and addresses
        """
        self.portals = []

    def add(self, item):
        """Add portal.

        Add entire structure, identical copies are stored in each pool so
        only one is needed.
        """
        if not self.portals and item:
            self.portals.extend(item)

    def purge(self, portals):
        """Remove target entries """
        for entry in self.portals:
            if not entry['name'] in portals:
                self.portals.remove(entry)

    def display(self):
        """Useful for debugging """
        pprint.pprint(self.portals)


class Targets(object):
    """Managers the targets.

    Manages the target section of the extended attributes (i.e. all data stored
    under targets).
    """

    def __init__(self):
        """List of targets.

        List of targets, entries are either host and iqn or hosts and iqn
        """
        self.targets = []

    def add(self, item):
        """Add a new target.

        Add entire structure, identical copies are stored in each pool so
        only one is needed.
        """
        if not self.targets and item:
            self.targets.extend(item)

    def display(self):
        """Useful for debugging """
        pprint.pprint(self.targets)

    def list(self):
        """Return only iqn values filtered by hostname """
        targets = []
        for entry in self.targets:
            if 'target' not in entry:
                raise RuntimeError(
                    "Missing keyword target from entry in targets section.")
            if 'hosts' in entry:
                for hentry in entry['hosts']:
                    if hentry['host'] in Common.hostname:
                        targets.append(entry['target'])
        return targets

    def portals(self):
        """Return the portals.

        Return only portal values filtered by hostname
        Return all portal values
        """
        portals = []
        for entry in self.targets:
            if 'hosts' in entry:
                for hentry in entry['hosts']:
                    portals.append(hentry['portal'])
        return portals

    def purge(self):
        """Remove all entries that do not match or contain hostname """
        for entry in self.targets:
            if 'host' in entry:
                if entry['host'] not in Common.hostname:
                    self.targets.remove(entry)
            if 'hosts' in entry:
                found = False
                for hentry in entry['hosts']:
                    if hentry['host'] in Common.hostname:
                        found = True
                if not found:
                    self.targets.remove(entry)


class Authentications(object):
    """Manages the auth section.

    Manages the authentication section under the extended attribute auth.
    This section is optional, but relates to gateways and targets
    independently.  Authentication can be none, tpg (common credentials),
    tpg+identified (common credentials, known initiators) or
    acls (host specific credentials).

    List of authentications.  Absent and present but disabled are
    permitted.
    """

    def __init__(self):
        self.authentications = []

    def add(self, item):
        """Add an auth.

        Add entire structure, identical copies are stored in each pool so
        only one is needed.
        """
        if not self._exists(item):
            self.authentications.append(item)

    def _exists(self, item):
        """Exists helper.

        helper function for above since "item in list" didn't work for
        list of lists
        """
        present = False
        for entry in self.authentications:
            for attr in ['host', 'target']:
                if attr in item and attr in entry:
                    if item[attr] == entry[attr]:
                        present = True
                        break
        return present

    def purge(self):
        """Removes authentication entries for other hosts """
        for entry in self.authentications:
            if 'host' in entry:
                if entry['host'] not in Common.hostname:
                    self.authentications.remove(entry)

    def display(self):
        """Useful for debugging """
        pprint.pprint(self.authentications)


class Gateways(object):
    """Manage gateways.

    Adds the gateways to the pools section.  If host_only is true, then
    only targets, authentications and portals referencing the host are
    kept.
    """

    def __init__(self, sections):
        """Keeps a running track of portals, initializes host_only

            sections = dict of configuration
        """
        self.portals = []
        self.sections = sections
        self.host_only = False

    def hostonly(self):
        """Enable host_only """
        self.host_only = True

    def find_portals(self):
        """Find all portals in the targets.

        Search for all portals listed in the targets section.  This is
        a no-op for the global configuration.
        """
        if self.host_only:
            self.targets = self.sections["targets"].list()
            for portal in self.sections["targets"].portals():
                self.portals.append(portal)

    def add(self, key, value, hostname):
        """Add a gateway specifically for a host or for all hosts """
        if self.host_only:
            if key in self.targets or key in hostname:
                content = json.loads(value,
                                     object_pairs_hook=OrderedDict)
                self.sections["pools"].append('gateways', content)
                for entry in content['tpg']:
                    if 'portal' in entry:
                        self.portals.append(entry['portal'])
        else:
            self.sections["pools"].append(
                'gateways', json.loads(value, object_pairs_hook=OrderedDict))

    def purge(self):
        """Removes configuration not containing host.

        No-op for global configuration.
        """
        if self.host_only:
            self.sections["targets"].purge()
            self.sections["authentications"].purge()
            self.sections["portals"].purge(self.portals)
