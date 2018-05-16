
import logging
import os
import re
from subprocess import PIPE
from subprocess import Popen
import uuid

from lrbd import content
from lrbd import runtime
from lrbd import utils

##########################################################################
# Ideal spot for separating into another file.  All classes and functions
# below change the host system.
##########################################################################


def find_auth(key):
    """Find the auth for host.

    Search for the matching host or target and return the authentication value

        key - string, host or target
    """

    for entry in content.Common.config['auth']:
        if 'host' in entry and entry['host'] == key:
            return entry['authentication']
        if 'target' in entry and entry['target'] == key:
            return entry['authentication']
    logging.warning("{} not found in auth".format(key))
    return ""


def iqn(entry):
    """Return the target iqn.

    if exists, otherwise default to the first iqn listed
    in the targets section, which is host specific.

        entry - a dictionary, typically an image entry
    """
    if 'target' in entry:
        return entry['target']
    else:
        return content.Common.config['iqns'][0]


class Images(object):
    """Manages mapping and unmapping RBD images """

    def __init__(self):
        """Parse and store 'rbd showmapped' """
        self.mounts = {}
        proc = Popen(["rbd", "showmapped"], stdout=PIPE, stderr=PIPE)
        for line in proc.stdout:
            results = re.split(r'\s+', line.decode('utf-8'))
            if results[0] == 'id':
                continue
            self.mounts[":".join([results[1], results[2]])] = results[4]

    def map(self):
        """Create the commands to map each rbd device.

        Allow custom fields for retries.
        """
        self.map_cmds = {}

        for pentry, gentry, entry in content.entries():
            if (":".join([pentry['pool'], entry['image']]) in
                    self.mounts.keys()):
                continue
            key = pentry['pool'] + ":" + entry['image']
            if key not in self.map_cmds:
                self.map_cmds[key] = {}
            self.map_cmds[key]['cmd'] = [
                "rbd", "-p", pentry['pool'], "--name",
                content.Common.client_name,
                "map", entry['image']]
            # Default list: 95, Operation not supported
            self.map_cmds[key]['custom'] = {'retry_errors': [95]}
            for attr in ['retries', 'sleep', 'retry_errors']:
                if attr in entry:
                    self.map_cmds[key]['custom'][attr] = entry[attr]

        for key in self.map_cmds.keys():
            cmd = self.map_cmds[key]['cmd']
            custom = self.map_cmds[key]['custom']
            utils.retry(cmd, **custom)

    def unmap(self):
        """Unmount all rbd images """
        for mount in self.mounts.keys():
            utils.popen(["rbd", "unmap", self.mounts[mount]])


class Backstores(object):
    """Backstore object for RBD Images.

    Creates the necessary backstores via targetcli for each RBD image.
    """

    def __init__(self, backstore):
        """Set selected backstore, load modules for rbd, create command"""
        self.cmds = []
        if backstore is None:
            self._detect()
        else:
            self.selected = backstore

        # Added to python-rtslib 104105
        # if (self.selected == "rbd"):
        #    self._load_modules()
        self._cmd()
        runtime.Runtime.config['backstore'] = self.selected

    def _detect(self):
        """Check for existing backstores.

        Check for existing backstores and set selected, otherwise default
        All images will be either iblock or rbd.  Last checked wins.
        """
        for pentry, gentry, entry in content.entries():
            existing = runtime.Runtime.core("*/{}".format(entry['image']))
            if existing:
                self.selected = re.split("[/_]", existing[0])[6]

        if not hasattr(self, 'selected'):
            # default
            self.selected = "rbd"

    def _cmd(self):
        """Generate the backstore commands, skip existing. """
        for pentry, gentry, entry in content.entries():

            name = runtime.Runtime.backstore(pentry['pool'], entry)
            cmd = ["targetcli", "/backstores/{}".format(self.selected),
                   "create", "name={}".format(name),
                   "dev=/dev/rbd/{}/{}".format(pentry['pool'],
                                               entry['image'])]
            backstore = runtime.Runtime.core("{}_*/{}".format(self.selected,
                                                              name))
            if not backstore:
                self.cmds.append(cmd)

    def _load_modules(self):
        """Same kernel modules as targetcli + target_core_rbd """
        modules = ["vhost_scsi", "iscsi_target_mod", "tcm_loop", "tcm_fc",
                   "ib_srpt", "tcm_qla2xxx", "target_core_rbd"]
        for module in modules:
            if not os.path.isdir("/sys/module/{}".format(module)):
                utils.popen(["modprobe", module])

    def create(self):
        """Execute saved commands """
        for cmd in utils.uniq(self.cmds):
            utils.popen(cmd)
        self._enable_rbd()

    def _enable_rbd(self):
        """Enable rbd.

        An image in an rbd backstore must be enabled prior to lun creation
        """

        for pentry, gentry, entry in content.entries():
            files = runtime.Runtime.core("rbd_*/{}/enable".
                                         format(entry['image']))
            for filename in files:
                enabled = open(filename).read().rstrip('\n')
                if enabled == "0":
                    with open(filename, "w") as enable:
                        enable.write("1")
                        logging.debug("Enabling {}".format(filename))


class BackstoreAttributes(object):
    """Attributes for Backstores.

    Allows the assignment of backstore attributes from each entry.
    """

    def __init__(self):
        """Object constructor.

        Define dict.  Set default values (e.g. "block_size": "1024") that
        are different than kernel default values
        """
        self.attributes = {}

    def assign(self):
        """Assign entries.

        Search entries for backstore_ prefixed attributes and add/overwrite
        dict values.  Save each.
        """
        once = True
        for pentry, gentry, entry in content.entries():
            name = runtime.Runtime.backstore(pentry['pool'], entry)
            _attributes = self.attributes.copy()
            for attr in entry:
                if re.match(r'backstore_', attr):
                    backstore_attr = re.sub(r'backstore_', '', attr)
                    _attributes[backstore_attr] = entry[attr]
                    if once:
                        logging.warning(
                            "Be aware that default values were used during "
                            "testing and understand the impact of changing "
                            "any backstore attributes.\n")
                        once = False

            self._save(name, _attributes)

    def _save(self, name, attributes):
        """Save the attributes.

        Find each pathname.  Compare contents with desired value.  Overwrite
        if necessary.
        """
        paths = runtime.Runtime.core("rbd_*/{}/attrib".format(name))
        for base in paths:
            for attr in attributes.keys():
                path = base + "/" + attr
                logging.debug("Backstore attribute path {}".format(path))
                if not os.path.isfile(path):
                    raise RuntimeError("No such attribute {}".format(attr))
                content = open(path).read().rstrip('\n')
                if attributes[attr] != content:
                    try:
                        logging.info("Setting {} to {}".
                                     format(attr, attributes[attr]))
                        file_attr = open(path, "w")
                        file_attr.write(attributes[attr] + "\n")
                        file_attr.close()
                    except IOError:
                        # Already in use
                        pass


class Iscsi(object):
    """Iscsi object.

    Creates iscsi entries with provided static target iqns or dynamically
    generates one if none are provided.
    """

    def __init__(self):
        """Constructor.

        Find all target entries in targets.  Append to cmds all that do not
        exist.  If no targets are provided, set cmds to a single base command.
        """
        self.cmds = []
        self.iqns = []

        self._arrange()
        wwn = WWN()
        wwn.generate(self.iqns)
        self._assign_vendor()

        base = ["targetcli", "/{}".format(runtime.Runtime.fabric), "create"]

        if self.iqns:
            for iqn in self.iqns:
                path = runtime.Runtime.path("{}".format(iqn))
                if not path:
                    cmd = list(base)
                    cmd.append(iqn)
                    self.cmds.append(cmd)
        else:
            cmd = base
            self.cmds.append(cmd)
            logging.warning(
                "No matching host found, generating dynamic target\n")

    def _arrange(self):
        """Keep the host entry target at the front of the list """
        for entry in content.Common.config['targets']:
            if 'host' in entry:
                self.iqns.insert(0, entry['target'])
            else:
                self.iqns.append(entry['target'])
            if ('hosts' in entry and
                    runtime.Runtime.config['backstore'] == "iblock"):
                logging.warning("Multiple gateway targets not supported " +
                                "with iblock backend, use rbd backend\n")

    def _assign_vendor(self):
        """Add branding """
        for pentry, gentry, entry in content.entries():
            name = runtime.Runtime.backstore(pentry['pool'], entry)
            path = runtime.Runtime.core(
                "{}_*/{}/wwn/vendor_id".format(
                    runtime.Runtime.config['backstore'], name))

            if path and os.path.isfile("/etc/SuSE-release"):
                try:
                    vendor = open(path[0], "w")
                    vendor.write("SUSE\n")
                    vendor.close()
                except IOError:
                    # Already in use
                    pass

    def create(self):
        """Create an iSCSI entry.

        Execute commands and assign list of targets to Common.config['iqns']
        """
        for cmd in self.cmds:
            utils.popen(cmd)
        if self.iqns:
            content.Common.config['iqns'] = self.iqns
        else:
            path = runtime.Runtime.path("iqn*")
            content.Common.config['iqns'] = [os.path.basename(path[0])]
        logging.debug("Common.config['iqns']: {}".
                      format(content.Common.config['iqns']))


class WWN(object):
    """World Wide Names obj.

    Manage the generation and assignment of unique serial numbers
    """

    def __init__(self):
        """Constructor.

        Initialize dicts _uuids and _generation.  Search configuration for
        optional settings.
        """
        self._uuids = {}
        self._generation = {}
        for entry in content.Common.config['targets']:
            if 'target' in entry:
                target = entry['target']
                if 'wwn_generate' in entry:
                    self._generation[target] = entry['wwn_generate']

    def generate(self, iqns):
        """Build the WWN list.

        Assign uuid for each entry.  Possible choices are
        1) Hardcoded assignment by configuration
        2) Original wwn generation including target + image
        3) Current default wwn generation including pool + target + image
        """
        if 'pools' in content.Common.config:
            for pentry, gentry, entry in content.entries():
                if 'target' in gentry:
                    target = gentry['target']
                else:
                    if iqns:
                        target = iqns[0]
                    else:
                        # None specified - rely on automatic generation
                        return
                if 'uuid' in entry:
                    _uuid = entry['uuid']
                    if not self._check_uuid(_uuid):
                        logging.warning(
                            "{} does not appear to be a UUID\n"
                            "EXAMPLE: 12345678-abcd-9012-efab-345678901234".
                            format(_uuid))

                else:
                    if (target in self._generation and
                            self._generation[target] == "original"):
                        _uuid = uuid.uuid3(uuid.NAMESPACE_DNS,
                                           str(target + entry['image']))
                    else:
                        _uuid = uuid.uuid3(uuid.NAMESPACE_DNS,
                                           str(pentry['pool'] + target +
                                               entry['image']))
                self._save(pentry, entry, target, _uuid)

    def _check_uuid(self, uuid):
        """Check that the uuid matches the uuid3 format """
        return re.match(
            r'[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-'
            '[\da-fA-F]{12}$', uuid)

    def _save(self, pentry, entry, target, uuid):
        """Write the uuid to the correct vpd_unit_serial file """
        logging.debug("For image {} on target {}\nuuid: {}".
                      format(entry['image'], target, uuid))
        name = runtime.Runtime.backstore(pentry['pool'], entry)
        path = runtime.Runtime.core(
            "{}_*/{}/wwn/vpd_unit_serial".format(
                runtime.Runtime.config['backstore'], name))
        try:
            vus = open(path[0], "w")
            vus.write(str(uuid) + "\n")
            vus.close()
        except IOError:
            # Already in use
            pass


class TPGs(object):
    """TPGs object.

    Creates any additional TPGs needed.
    """

    def __init__(self, tpg_counter, portal_index, lun_assignment):
        """Track several states.

            self.cmds - final list of commands to be executed
            self.tpg_counter - object that tracks the allocated TPGs per target
            self.portal_index - object that tracks associations of TPGs and
                                portals
            self.lun_assignment - object that tracks hardcoded LUNs
        """
        self.cmds = []
        runtime.Runtime.config['addresses'] = utils.addresses()

        self.tpg_counter = tpg_counter
        self.portal_index = portal_index
        self.lun_assignment = lun_assignment

        self._add()
        runtime.Runtime.config['portals'] = self.portal_index.portals

    def _add(self):
        """Add new TPG.

        Adds a TPG for each portal group.  Since iscsi.create() makes tpg1,
        skips that one naturally.
        """
        last_pool = None
        for pentry, gentry, entry in content.entries():
            if (last_pool != pentry['pool']):
                self.tpg_counter.reset_all()
            target = iqn(gentry)
            self.tpg_counter.add(target)
            if 'lun' in entry:
                self.lun_assignment.assign(
                    target, entry['image'], entry['lun'])
            logging.debug("_add: {}, {}".format(target, entry['image']))
            self.portal_index.add(target, entry['image'])

            if 'target' in gentry:
                self._add_target(target)
            else:
                self._add_host(entry, target)

            last_pool = pentry['pool']

    def _add_target(self, target):
        """Adds TPG for each portal on a host.

        Adds a TPG for each portal on this host.  Effectively multiplies the
        number of defined groups of TPGs by the number of portal groups.  Each
        gateway will create the same ordering so a specific image will be the
        same TPG and index on every gateway.

            target - target iqn
        """
        for tentry in content.Common.config['targets']:
            if target == tentry['target']:
                for hentry in tentry['hosts']:
                    if not hentry['portal'] in self.portal_index.list():
                        self.portal_index.index(hentry['portal'])
                        self._add_command(target)
                        self.tpg_counter.next()

    def _add_command(self, target):
        """Append command with current counter """
        self.portal_index.tpg(self.tpg_counter.value())
        self.cmds.append(self._cmd(target, self.tpg_counter.value()))
        logging.debug("Adding TPG {} for target {}".
                      format(self.tpg_counter.value(), target))

    def _add_host(self, entry, target):
        """Adds a tpg for the specified entry.

            entry - a dict containing portal, initiator and image keys
            target - target iqn
        """
        if 'portal' in entry:
            allocated_tpg = self.portal_index.find(entry['portal'])
            self.portal_index.index(entry['portal'])
            if allocated_tpg:
                self.portal_index.tpg(allocated_tpg)

            if not entry['portal'] in self.portal_index.list():
                self._check_portal(entry['portal'])
                self._add_command(target)
                self.tpg_counter.next()
        else:
            self.portal_index.index = 'default'
            self._add_command(target)
            self.tpg_counter.next()

    def _check_portal(self, name):
        """Check that the referenced portal is defined in portals """
        found = False
        for entry in content.Common.config['portals']:
            if name == entry['name']:
                found = True
                break
        if not found:
            raise ValueError("portal {} is missing from portals".format(name))

    def disable_remote(self):
        """Find non-local portals on each tpg and disable """
        for target, image, portal, tpg in self.portal_index.entries():
            for entry in content.Common.config['portals']:
                if portal == entry['name']:
                    for address in entry['addresses']:
                        addr = re.split(" ", address)[0]
                        if addr not in runtime.Runtime.config['addresses']:
                            self._disable_tpg(target, tpg)

    def disable_all(self):
        """Find all portals on each tpg and disable """
        for target, image, portal, tpg in self.portal_index.entries():
            for entry in content.Common.config['portals']:
                if portal == entry['name']:
                    self._disable_tpg(target, tpg)

    def enable_local(self):
        """Find local portals on each tpg and enable """
        for target, image, portal, tpg in self.portal_index.entries():
            for entry in content.Common.config['portals']:
                if portal == entry['name']:
                    for address in entry['addresses']:
                        addr = re.split(" ", address)[0]
                        if addr in runtime.Runtime.config['addresses']:
                            self._enable_tpg(target, tpg)

    def _disable_tpg(self, target, tpg):
        """Disable TPG and disable tpg_enabled_sendtargets.  """
        path = runtime.Runtime.path(
            "{}/tpgt_{}/attrib/tpg_enabled_sendtargets".format(target, tpg))[0]
        if not os.path.isfile(path):
            raise RuntimeError(
                "tpg_enabled_sendtargets unsupported, "
                "upgrade kernel to 3.12.46-102-default or higher")
        tes = open(path, "w")
        tes.write("0")
        tes.close()
        logging.debug("Disabling tpg_enabled_sendtargets for tpg " +
                      "{} under target {}".format(tpg, target))
        tpg_path = runtime.Runtime.path(
            "{}/tpgt_{}/enable".format(target, tpg))[0]
        enabled = open(tpg_path).read().rstrip('\n')
        if enabled == "1":
            utils.popen(["targetcli", "/{}/{}/tpg{}".
                         format(runtime.Runtime.fabric, target, tpg),
                         "disable"])

    def _enable_tpg(self, target, tpg):
        """Enable TPG and enable tpg_enabled_sendtargets.  """
        path = runtime.Runtime.path(
            "{}/tpgt_{}/attrib/tpg_enabled_sendtargets".format(target, tpg))[0]
        if not os.path.isfile(path):
            raise RuntimeError(
                "tpg_enabled_sendtargets unsupported, "
                "upgrade kernel to 3.12.46-102-default or higher")
        tes = open(path, "w")
        tes.write("1")
        tes.close()
        logging.debug("Enabling tpg_enabled_sendtargets for tpg " +
                      "{} under target {}".format(tpg, target))
        tpg_path = runtime.Runtime.path(
            "{}/tpgt_{}/enable".format(target, tpg))[0]
        enabled = open(tpg_path).read().rstrip('\n')
        if enabled == "0":
            utils.popen(["targetcli", "/{}/{}/tpg{}".
                         format(runtime.Runtime.fabric, target, tpg),
                         "enable"])

    def _cmd(self, target, tpg):
        """Return targetcli command if configfs entry is not present """
        path = runtime.Runtime.path("{}/tpgt_{}".format(target, tpg))
        if not path:
            return ["targetcli", "/{}/{}".
                    format(runtime.Runtime.fabric, target),
                    "create {}".format(tpg)]
        return []

    def create(self):
        """Execute.

        Execute commands and assign list of targets to Common.config['iqns']
        """
        for cmd in self.cmds:
            if cmd:
                utils.popen(cmd)


class TPGCounter(object):
    """Track the number of Target Portal Groups """

    def __init__(self):
        """Track counter """
        self.tpg = {}
        self.target = None

    def add(self, target):
        """Initializing """
        self.tpg[target] = 1
        self.target = target
        logging.debug("Initializing target {}".format(target))

    def value(self):
        """Return tpg value """
        return self.tpg[self.target]

    def next(self):
        """Increment for next target """
        self.tpg[self.target] += 1

    def reset_all(self):
        """Reset all tpg counters.  """
        for target in self.tpg:
            self.tpg[target] = 1


class PortalIndex(object):
    """Track the associated TPG for each portal """

    def __init__(self):
        """Initialize two dimensional dictionary and state """
        self.portals = {}

        self.target = None
        self.image = None
        self.portal = None

    def add(self, target, image):
        """Creates structure and sets context """
        logging.debug("Adding PortalIndex: {}, {}".format(target, image))
        if target not in self.portals:
            self.portals[target] = {}
        if image not in self.portals[target]:
            self.portals[target][image] = {}
        self.target = target
        self.image = image

    def list(self):
        """List.

        Returns dictionary of portals already allocated for this target and
        image
        """
        return self.portals[self.target][self.image]

    def index(self, value):
        """Assign portal name """
        self.portal = value

    def tpg(self, value):
        """Assign tpg to current context """
        self.portals[self.target][self.image][self.portal] = value

    def find(self, name):
        """Find.

        Search for a specific portal and return the tpg; otherwise,
        return False
        """
        for target, image, portal, tpg in self.entries():
            if (name == portal):
                return tpg
        return False

    def entries(self):
        """Generator """
        for target in self.portals.keys():
            for image in self.portals[target].keys():
                for portal in self.portals[target][image].keys():
                    yield(target, image, portal,
                          self.portals[target][image][portal])


class LunAssignment(object):
    """Manages the assignment of hardcode LUNs """

    def __init__(self):
        """Constructor.

        Track assignments and used LUNs.  The keys/values are inverted from the
        other.
        """
        self.assignments = {}
        self.used = {}

    def assign(self, target, image, lun):
        """Create necessary structure and assign values """
        if target not in self.assignments:
            self.assignments[target] = {}
            self.used[target] = {}
        if lun in self.used[target]:
            raise ValueError(
                "Lun {} already allocated for image {} in target {}".
                format(lun, self.used[target][lun], target))
        self.assignments[target][image] = lun
        self.used[target][lun] = image

    def assigned(self, target, image):
        """Return the assigned lun for the given target and image """
        if (target in self.assignments and
                image in self.assignments[target]):
            return(self.assignments[target][image])
        return None


class TPGattributes(object):
    """Manage TPG attributes.

    Allows the assignment of tpg attributes.  Any defined with the target
    affect all related images.
    """

    def __init__(self):
        """Constructor.

        Define dict.  Set default values (e.g. "login_timeout": "10") that
        are different than kernel default values
        """
        self.attributes = {}

    def assign(self):
        """Assign attribute.s

        Search targets and entries for tpg_ prefixed attributes and
        add/overwrite dict values.  Save each.
        """

        once = True
        for tentry in content.Common.config['targets']:
            for attr in tentry:
                if re.match(r'tpg_', attr):
                    tpg_attr = re.sub(r'tpg_', '', attr)
                    self.attributes[tpg_attr] = tentry[attr]
                    if once:
                        logging.warning(
                            "Be aware that default values were used during "
                            "testing and understand the impact of changing "
                            "any TPG attributes.\n")
                        once = False
            self._save(tentry['target'])

    def _save(self, target):
        """Save.

        Find each pathname.  Compare contents with desired value.  Overwrite
        if necessary.
        """
        paths = runtime.Runtime.path("{}/tpgt_*/attrib".format(target))
        for base in paths:
            for attr in self.attributes.keys():
                path = base + "/" + attr
                logging.debug("TPG attribute path {}".format(path))
                if not os.path.isfile(path):
                    raise RuntimeError("No such attribute {}".format(attr))
                content = open(path).read().rstrip('\n')
                if self.attributes[attr] != content:
                    try:
                        logging.info("Setting {} to {}".
                                     format(attr, self.attributes[attr]))
                        file_attr = open(path, "w")
                        file_attr.write(self.attributes[attr] + "\n")
                        file_attr.close()
                    except IOError:
                        # Already in use
                        pass


class Portals(object):
    """Manager Portals.

    Manage the creation of portals, skipping existing.  If none are provided
    in the configuration, assign the base targetcli command which selects
    a default interface.
    """

    def __init__(self):
        """Constructor.

        Build portal commands, assign address to correct TPG
        """
        self.cmds = []
        self.luns = []

        if ('portals' in content.Common.config and
                content.Common.config['portals']):
            for target, image, portal, entry in self._entries():
                if entry['name'] == portal:
                    for address in entry['addresses']:
                        # self._cmd(target,
                        #  Runtime.config['portals'][target][image][portal],
                        self._cmd(target,
                                  runtime.Runtime.tpg(target, image, portal),
                                  address)
                        logging.debug(
                            "Adding address {} to tpg {} under target {}".
                            format(address,
                                   runtime.Runtime.tpg(target, image, portal),
                                   target))
        else:
            self._cmd(iqn({}), "1", "")

    def _entries(self):
        """Generator """
        for target in runtime.Runtime.targets():
            for image in runtime.Runtime.images(target):
                for portal in runtime.Runtime.portals(target, image):
                    self._check(portal)
                    for entry in content.Common.config['portals']:
                        yield(target, image, portal, entry)

    def _check(self, name):
        """Verification check.

        Simple verification to check the portal referenced is defined

            name - name of portal
        """
        found = False
        if name == "default":
            found = True
        for entry in content.Common.config['portals']:
            if entry['name'] == name:
                found = True

        if not found:
            raise ValueError(
                "portal {} missing from portals section".format(name))

    def _cmd(self, target, tpg, address):
        """Execute.

        Compose targetcli commmand for creating portal if needed. Convert
        address from space to colon delimited, if needed.
        """
        cmd = ["targetcli",
               "/{}/{}/tpg{}/portals".
               format(runtime.Runtime.fabric, target, tpg),
               "create", address]
        portal = runtime.Runtime.path(
            "{}/tpgt_{}/np/{}*".format(
                target, tpg, re.sub(r' ', ':', address)))
        if not portal:
            self.cmds.append(cmd)

    def create(self):
        """Create.

        Execute saved commands.  Skip redundant commands from multiple image
        entries.
        """
        # for cmd in uniq(self.cmds):
        for cmd in utils.uniq(self.cmds):
            utils.popen(cmd)


class Luns(object):
    """Manage Luns.

    Manages the creation of luns.  Also, provides method for
    disabling auto add which is necessary for acls.
    """

    def __init__(self, lun_assignment):
        """Constructor.

        Skips existing luns.  Builds commands for each image under the
        correct target.
        """
        # self.cmds = []
        self.assigned = []
        self.unassigned = []
        self.exists = {}
        self.name = None
        self.lun_assignment = lun_assignment

        self._find()

        for pentry, gentry, entry in content.entries():
            target = iqn(gentry)
            self.name = runtime.Runtime.backstore(pentry['pool'], entry)
            if 'target' in gentry:
                for image in runtime.Runtime.images(target):
                    if image == entry['image']:
                        for portal in runtime.Runtime.portals(target, image):
                            tpg = str(
                                runtime.Runtime.tpg(target, image, portal))

                            self._add_command(target, tpg, entry)
            else:
                tpg = str(runtime.Runtime.tpg(target, entry))
                self._add_command(target, tpg, entry)

    def _add_command(self, target, tpg, entry):
        """Append to existing commands if necessary """
        if not (target in self.exists and
                tpg in self.exists[target] and
                entry['image'] in self.exists[target][tpg]):
            self._cmd(target, tpg, entry['image'])
            logging.debug("Adding lun for image {} to tpg {} under target {}".
                          format(entry['image'], tpg, target))

    def _find(self):
        """Scan paths for existing luns and save lun name to list """
        for pentry, gentry, entry in content.entries():
            target = iqn(gentry)
            udev_paths = runtime.Runtime.path(
                "{}/tpgt_*/lun/lun_*/*/udev_path".format(target))
            if target not in self.exists:
                self.exists[target] = {}
            for udev_path in udev_paths:
                contents = open(udev_path).read().rstrip('\n')
                tpg = re.split("[/_]", udev_path)[8]
                if tpg not in self.exists[target]:
                    self.exists[target][tpg] = []
                self.exists[target][tpg].append(os.path.basename(contents))

    def _cmd(self, target, tpg, image):
        """Compose targetcli commmand for creating lun if needed.  """
        if runtime.Runtime.config['backstore'] == "rbd":
            cmd = ["targetcli",
                   "/{}/{}/tpg{}/luns".
                   format(runtime.Runtime.fabric, target, tpg),
                   "create", "/backstores/rbd/{}".format(self.name)]
        else:
            cmd = ["targetcli",
                   "/{}/{}/tpg{}/luns".
                   format(runtime.Runtime.fabric, target, tpg),
                   "create", "/backstores/iblock/{}".format(self.name)]

        _lun = self.lun_assignment.assigned(target, image)
        if _lun:
            cmd.append(_lun)
            self.assigned.append(cmd)
        else:
            self.unassigned.append(cmd)
        # self.cmds.append(cmd)

    def create(self):
        """Disable auto mapping.  Execute saved commands.  """
        self.disable_auto_add_mapped_luns()
        for cmd in utils.uniq(self.assigned):
            utils.popen(cmd)
        for cmd in utils.uniq(self.unassigned):
            utils.popen(cmd)

    def disable_auto_add_mapped_luns(self):
        """Allow device to initiator mapping by disabling auto mapping.  """
        proc = Popen(["targetcli", "get", "global", "auto_add_mapped_luns"],
                     stdout=PIPE, stderr=PIPE)
        for line in proc.stdout:
            results = re.split(r'=', line.decode('utf-8'))
            if results[1].rstrip() != 'false':
                cmd = ["targetcli", "set", "global",
                       "auto_add_mapped_luns=false"]
                utils.popen(cmd)


class Map(object):
    """Manages the mapping of LUNs specifically for acls """

    def __init__(self):
        """Creates mapped luns under each initiator.  Skips existing.  """
        self.cmds = []
        self.luns = []

        for pentry, gentry, entry in content.entries():
            target = iqn(gentry)
            self.name = runtime.Runtime.backstore(pentry['pool'], entry)
            if 'target' in gentry:
                if self._check_auth(gentry['target']):
                    self._check_initiator(entry, target, gentry['target'])
                    for image in runtime.Runtime.images(target):
                        if image == entry['image']:
                            for portal in runtime.Runtime.portals(target,
                                                                  image):
                                tpg = runtime.Runtime.tpg(
                                    target, image, portal)
                                self._add_command(target, tpg, entry)
            else:
                if self._check_auth(gentry['host']):
                    self._check_initiator(entry, target, gentry['host'])
                    tpg = str(runtime.Runtime.tpg(target, entry))
                    self._add_command(target, tpg, entry)

    def _check_auth(self, target_auth):
        """Checks appropriate authentication types """
        return (find_auth(target_auth) == "acls" or
                find_auth(target_auth) == "tpg+identified")

    def _check_initiator(self, entry, target, target_auth):
        """Safety check """
        if 'initiator' not in entry:
            raise RuntimeError(
                "Entry for target {} missing initiator for specified "
                "authentication {}".format(target,
                                           find_auth(target_auth)))

    def _add_command(self, target, tpg, entry):
        """Builds command """
        lun = self._lun(target, tpg, entry['image'])
        self._check(target, tpg, entry['initiator'])
        self._cmd(target, tpg, entry['initiator'], lun)
        logging.debug(
            "Mapping lun {} for initiator {} to tpg {} under target {}".
            format(lun, entry['initiator'], tpg, target))

    def _lun(self, target, tpg, image):
        """Return the numeric value of the lun for this image

            image - name of RBD image
        """
        lun_path = runtime.Runtime.path(
            "{}/tpgt_{}/lun/lun_*/*".format(target, tpg))
        logging.debug("lun path: {}".format(lun_path))
        for path in lun_path:
            if os.path.basename(os.path.realpath(path)) == self.name:
                return re.split("[/_]", path)[11]

        raise ValueError("lun missing from tpg{} under target {}".
                         format(tpg, target))

    def _check(self, target, tpg, initiator):
        """Check that acl exists, otherwise, raise exception

            target - iqn of the target
            tpg - number of tpg, most likely "1"
            initiator - iqn of client
        """
        path = runtime.Runtime.path(
            "{}/tpgt_{}/acls/{}".format(target, tpg, initiator))
        if not path:
            raise ValueError("ERROR: acl missing for initiator " +
                             "{} under tpg {} under target {}".
                             format(initiator, tpg, target))

    def _cmd(self, target, tpg, initiator, lun):
        """Compose command to create a mapped lun.  Skip if exists.

            target - iqn of the target
            tpg - number of tpg, most likely "1"
            initiator - iqn of client
            lun - number for block device of RBD image
        """
        path = runtime.Runtime.path("{}/tpgt_{}/acls/{}/lun_{}".
                                    format(target, tpg, initiator, lun))
        if not path:
            self.cmds.append(
                ["targetcli",
                 "/{}/{}/tpg{}/acls/{}".
                 format(runtime.Runtime.fabric, target, tpg, initiator),
                 "create", lun, lun])

    def map(self):
        """Execute saved commands.  """
        for cmd in self.cmds:
            utils.popen(cmd)


class Acls(object):
    """Manage ACLs.

    Manage acls for each initiator.  Skip existing entries.

    """

    def __init__(self):
        """Constructor.

        Create acl under correct tpg per target.  Skip existing.
        Scan portal addresses for remote gateways.  Create acl under remote
        tpg, if necessary.
        """
        self.cmds = []
        self.initiators = []
        self.exists = {}

        self._find()
        for pentry, gentry, entry in content.entries():
            target = iqn(gentry)
            if 'target' in gentry:
                if self._check_auth(gentry['target']):
                    self._check_initiator(entry, target, gentry['target'])
                    for image in runtime.Runtime.images(target):
                        if image == entry['image']:
                            for portal in runtime.Runtime.portals(target,
                                                                  image):
                                tpg = str(runtime.Runtime.tpg(target, image,
                                                              portal))
                                self._add_command(target, tpg, entry)
            else:
                if self._check_auth(gentry['host']):
                    self._check_initiator(entry, target, gentry['host'])
                    tpg = str(runtime.Runtime.tpg(target, entry))
                    self._add_command(target, tpg, entry)

    def _check_auth(self, target_auth):
        return (find_auth(target_auth) == "acls" or
                find_auth(target_auth) == "tpg+identified")

    def _check_initiator(self, entry, target, target_auth):
        if 'initiator' not in entry:
            raise RuntimeError("Entry for target " +
                               "{} ".format(target) +
                               "missing initiator for specified " +
                               "authentication " +
                               "{}".format(find_auth(target_auth)))

    def _add_command(self, target, tpg, entry):
        if not (target in self.exists and
                tpg in self.exists[target] and
                entry['initiator'] in self.exists[target][tpg]):
            self._cmd(target, tpg, entry['initiator'])
            logging.debug("Adding initiator {} under tpg {} for target {}".
                          format(entry['initiator'], tpg, target))

    def _find(self):
        """Add existing initiators to list """
        for pentry in content.Common.config['pools']:
            if 'gateways' in pentry:
                for gentry in pentry['gateways']:
                    target = iqn(gentry)
                    if target not in self.exists:
                        self.exists[target] = {}
                    paths = runtime.Runtime.path(
                        "{}/tpgt_*/acls/*".format(target))
                    for path in paths:
                        self.initiators.append(os.path.basename(path))
                        tpg = re.split("[/_]", path)[8]
                        if tpg not in self.exists[target]:
                            self.exists[target][tpg] = []
                        self.exists[target][tpg].append(os.path.basename(path))

    def _cmd(self, target, tpg, initiator):
        """Execute.

        Compose targetcli command for creating an acl.  Append to list.
        """
        cmd = ["targetcli",
               "/{}/{}/tpg{}/acls".format(runtime.Runtime.fabric, target, tpg),
               "create", initiator]
        self.cmds.append(cmd)

    def create(self):
        """Execute unique, saved commands """
        for cmd in utils.uniq(self.cmds):
            utils.popen(cmd)


class Auth(object):
    """Manage Auth for targets.

    Manage the authentications for each target.  Each authentication mode
    contains multiple steps.  Delegate creation of the necessary commands.
    Execute commands.
    """

    def __init__(self):
        """Constructor.

        Check for existence of the authentication section and current setting.
        Select appropriate delegation.  Note that discovery authentication
        is independent of normal authentication and optional.
        """
        self.cmds = []
        self.tpg = {}

        if 'auth' in content.Common.config and content.Common.config['auth']:
            for auth in content.Common.config['auth']:
                for target in runtime.Runtime.targets():
                    if target == iqn(auth):
                        self.target = target
                        for image in runtime.Runtime.images(target):
                            for portal in runtime.Runtime.portals(target,
                                                                  image):
                                self.tpg = str(
                                    runtime.Runtime.tpg(target, image, portal))
                                self.auth = auth
                                self.select_auth()
                                self.cmds.extend(self.select_discovery())
        else:
            for target in runtime.Runtime.targets():
                self.target = target
                for image in runtime.Runtime.images(target):
                    for portal in runtime.Runtime.portals(target, image):
                        self.tpg = str(runtime.Runtime.tpg(target, image,
                                                           portal))
                        self.cmds.append(self.set_noauth())
            self.cmds.append(self.set_discovery_off())

    def select_auth(self):
        """Delegate authentication """
        if self.auth['authentication'] == "none":
            self.cmds.append(self.set_noauth())
        elif self.auth['authentication'] == "tpg":
            self.cmds.extend(self.select_tpg())
        elif self.auth['authentication'] == "tpg+identified":
            self._generate_acls()
            self.cmds.extend(self.select_acls())
        elif self.auth['authentication'] == "acls":
            self.cmds.extend(self.select_acls())
        else:
            raise ValueError("InvalidAuthentication: authentication must " +
                             "be one of tpg, tpg+identified, acls or none")

    def _generate_acls(self):
        """Generate ACLs.

        Create or append to the acls array the common tpg entry for each
        initiator.  This is technically the same as specifying acls with
        the same userid/password/etc.
        """
        for initiator in self._find_tpg_identified_initiators():
            if 'acls' not in self.auth:
                self.auth['acls'] = []
            entry = {}
            entry['initiator'] = initiator
            entry['userid'] = self.auth['tpg']['userid']
            entry['password'] = self.auth['tpg']['password']

            if 'mutual' in self.auth['tpg']:
                entry['mutual'] = self.auth['tpg']['mutual']
            if 'userid_mutual' in self.auth['tpg']:
                entry['userid_mutual'] = self.auth['tpg']['userid_mutual']
            if 'password_mutual' in self.auth['tpg']:
                entry['password_mutual'] = self.auth['tpg']['password_mutual']
            self.auth['acls'].append(entry)

    def _find_tpg_identified_initiators(self):
        """Search for all initiators for current tpg+identified entry """
        initiators = []
        for pentry, gentry, entry in content.entries():
            for key in ['target', 'host']:
                if (key in self.auth and key in gentry and
                        self.auth[key] == gentry[key]):
                    initiators.append(entry['initiator'])
        return initiators

    def set_noauth(self):
        """Disable authentication """
        logging.debug("Disable authentication")
        path = runtime.Runtime.path(
            "{}/tpgt_{}/attrib".format(self.target, self.tpg))[0]
        authentication = open(path + "/authentication").read().rstrip('\n')
        demo_mode_write_protect = open(
            path + "/demo_mode_write_protect").read().rstrip('\n')

        if authentication == "0" and demo_mode_write_protect == "0":
            return []

        cmd = ["targetcli",
               "/{}/{}/tpg{}".
               format(runtime.Runtime.fabric, self.target, self.tpg),
               "set", "attribute", "authentication=0",
               "demo_mode_write_protect=0", "generate_node_acls=1"]
        return cmd

    def select_discovery(self):
        """Select Discovery.

        Discovery is optional, can be completely disabled, have only mutual
        disabled or be completely enabled.  Delegate appropriately.
        """
        cmds = []
        for auth in content.Common.config['auth']:
            if "discovery" in auth:
                if auth['discovery']['auth'] == "enable":
                    self.d_auth = auth
                    if "mutual" in auth['discovery']:
                        if auth['discovery']['mutual'] == "enable":
                            cmds.append(self.set_discovery_mutual())
                        else:
                            cmds.append(self.set_discovery())
                    else:
                        cmds.append(self.set_discovery())
                else:
                    cmds.append(self.set_discovery_off())
            else:
                cmds.append(self.set_discovery_off())
            return cmds

    def set_discovery(self):
        """Set Discovery.

        Call targetcli to only set the discovery userid and password.  Check
        current settings.
        """
        logging.debug("Set discovery authentication")
        keys = ['userid', 'password']
        utils.check_keys(
            keys, self.d_auth['discovery'], "discovery under auth")

        path = runtime.Runtime.path("discovery_auth")[0]
        current = {}
        current['userid'] = open(path + "/userid").read().rstrip('\n')
        current['password'] = open(path + "/password").read().rstrip('\n')

        if utils.compare_settings(keys, current, self.d_auth['discovery']):
            return []

        cmd = ["targetcli", "/{}".format(runtime.Runtime.fabric),
               "set", "discovery_auth", "enable=1",
               "userid={}".format(self.d_auth['discovery']['userid']),
               "password={}".format(self.d_auth['discovery']['password'])]
        return cmd

    def set_discovery_mutual(self):
        """Set discovery mutual.

        Call targetcli to set both normal and mutual discovery authentication.
        Checks current settings.
        """
        logging.debug("Set discovery and mutual authentication")
        keys = ['userid', 'password', 'userid_mutual', 'password_mutual']
        utils.check_keys(
            keys, self.d_auth['discovery'], "discovery under auth")

        path = runtime.Runtime.path("discovery_auth")[0]
        current = {}
        current['userid'] = open(path + "/userid").read().rstrip('\n')
        current['password'] = open(path + "/password").read().rstrip('\n')
        current['userid_mutual'] = open(
            path + "/userid_mutual").read().rstrip('\n')
        current['password_mutual'] = open(
            path + "/password_mutual").read().rstrip('\n')

        if utils.compare_settings(keys, current, self.d_auth['discovery']):
            return []

        cmd = ["targetcli", "/{}".format(runtime.Runtime.fabric), "set",
               "discovery_auth", "enable=1",
               "userid={}".format(self.d_auth['discovery']['userid']),
               "password={}".format(self.d_auth['discovery']['password']),
               "mutual_userid={}".format(
                   self.d_auth['discovery']['userid_mutual']),
               "mutual_password={}".format(
                   self.d_auth['discovery']['password_mutual'])]
        return cmd

    def set_discovery_off(self):
        """Disable discovery """
        logging.debug("Disable discovery authentication")
        path = runtime.Runtime.path("discovery_auth")[0]
        enforce = open(path + "/enforce_discovery_auth").read().rstrip('\n')
        if enforce == "0":
            return []

        cmd = ["targetcli", "/{}".format(runtime.Runtime.fabric), "set",
               "discovery_auth", "enable=0"]
        return cmd

    def select_tpg(self):
        """Select TPG.

        TPG is optional, can have only mutual disabled or be completely
        enabled.  Delegate appropriately.  TPG allows a common userid and
        password for all initiators. Works for tpg and tpg+identified.
        """
        cmds = []
        if "mutual" in self.auth['tpg']:
            if self.auth['tpg']['mutual'] == "enable":
                cmds.append(self.set_tpg_mutual())
                cmds.append(self.set_tpg_mode())
            else:
                cmds.append(self.set_tpg())
                cmds.append(self.set_tpg_mode())
        else:
            cmds.append(self.set_tpg())
            cmds.append(self.set_tpg_mode())
        return cmds

    def set_tpg(self):
        """Set TPG.

        Call targetcli to set only the common userid and password.  Check
        current setting.
        """
        logging.debug("Set tpg authentication")
        keys = ['userid', 'password']
        utils.check_keys(keys, self.auth['tpg'], "tpg under auth")

        path = runtime.Runtime.path(
            "{}/tpgt_{}/auth".format(self.target, self.tpg))[0]
        current = {}
        current['userid'] = open(path + "/userid").read().rstrip('\n')
        current['password'] = open(path + "/password").read().rstrip('\n')

        if utils.compare_settings(keys, current, self.auth['tpg']):
            return []

        cmd = ["targetcli",
               "/{}/{}/tpg{}".format(
                   runtime.Runtime.fabric, self.target, self.tpg),
               "set", "auth",
               "userid={}".format(self.auth['tpg']['userid']),
               "password={}".format(self.auth['tpg']['password'])]
        return cmd

    def set_tpg_mutual(self):
        """Set TPG mutual mode.

        Call targetcli to set both the common and mutual userids and passwords.
        Checks current settings.
        """
        logging.debug("Set tpg and mutual authentication")
        keys = ['userid', 'password', 'userid_mutual', 'password_mutual']
        utils.check_keys(keys, self.auth['tpg'], "tpg under auth")

        path = runtime.Runtime.path(
            "{}/tpgt_{}/auth".format(self.target, self.tpg))[0]
        current = {}
        current['userid'] = open(path + "/userid").read().rstrip('\n')
        current['password'] = open(path + "/password").read().rstrip('\n')
        current['userid_mutual'] = open(
            path + "/userid_mutual").read().rstrip('\n')
        current['password_mutual'] = open(
            path + "/password_mutual").read().rstrip('\n')

        if utils.compare_settings(keys, current, self.auth['tpg']):
            return []

        cmd = ["targetcli",
               "/{}/{}/tpg{}".format(
                   runtime.Runtime.fabric, self.target, self.tpg),
               "set", "auth",
               "userid={}".format(self.auth['tpg']['userid']),
               "password={}".format(self.auth['tpg']['password']),
               "userid_mutual={}".format(self.auth['tpg']['userid_mutual']),
               "password_mutual={}".format(
                   self.auth['tpg']['password_mutual'])]
        return cmd

    def set_tpg_mode(self):
        """Set the TPG mode.

        Enable authentication, allow writing and enable acl generation. Checks
        current settings.
        """
        path = runtime.Runtime.path(
            "{}/tpgt_{}/attrib".format(self.target, self.tpg))[0]
        authentication = open(path + "/authentication").read().rstrip('\n')
        demo_mode_write_protect = open(
            path + "/demo_mode_write_protect").read().rstrip('\n')
        generate_node_acls = open(
            path + "/generate_node_acls").read().rstrip('\n')

        if self.auth['authentication'] == "tpg":
            if (authentication == "1" and
                    demo_mode_write_protect == "0" and
                    generate_node_acls == "1"):
                return []

            return(["targetcli",
                    "/{}/{}/tpg{}".format(
                        runtime.Runtime.fabric, self.target, self.tpg),
                    "set", "attribute", "authentication=1",
                    "demo_mode_write_protect=0", "generate_node_acls=1"])
        else:
            # tpg+identified
            if (authentication == "1" and
                    demo_mode_write_protect == "0" and
                    generate_node_acls == "0"):
                return []

            return ["targetcli",
                    "/{}/{}/tpg{}".format(
                        runtime.Runtime.fabric, self.target, self.tpg),
                    "set", "attribute", "authentication=1",
                    "demo_mode_write_protect=0", "generate_node_acls=0"]

    def select_acls(self):
        """Select ACLs.

        ACLs are optional, can have only mutual disabled or be completely
        enabled for each initiator.  Delegate appropriately.  ACLs allow a
        unique userid and password for each initiator.

        """
        cmds = []
        for acl in self.auth['acls']:
            self.acl = acl
            if "mutual" in acl:
                if acl['mutual'] == "enable":
                    cmds.append(self.set_acls_mutual())
                else:
                    cmds.append(self.set_acls())
            else:
                cmds.append(self.set_acls())
        cmds.append(self.set_acls_mode())
        return cmds

    def set_acls(self):
        """Set the ACLs.

        Call targetcli to set a userid and password for a specific initiator.
        Checks current setting.
        """
        logging.debug("Set acl authentication")
        keys = ['userid', 'password']
        utils.check_keys(keys, self.acl, "acl")

        path = runtime.Runtime.path(
            "{}/tpgt_{}/acls/{}/auth".format(
                self.target, self.tpg, self.acl['initiator']))[0]
        current = {}
        current['userid'] = open(path + "/userid").read().rstrip('\n')
        current['password'] = open(path + "/password").read().rstrip('\n')

        if utils.compare_settings(keys, current, self.acl):
            return []

        cmd = ["targetcli",
               "/{}/{}/tpg{}/acls/{}".format(
                   runtime.Runtime.fabric, self.target,
                   self.tpg, self.acl['initiator']),
               "set", "auth",
               "userid={}".format(self.acl['userid']),
               "password={}".format(self.acl['password']), ]
        return cmd

    def set_acls_mutual(self):
        """Set mutual auth.

        Call targetcli to set both a normal and mutual authentication for
        an initiator.  Checks current settings.
        """
        logging.debug("Set acl and mutual authentication")
        keys = ['userid', 'password', 'userid_mutual', 'password_mutual']
        utils.check_keys(keys, self.acl, "acl")

        path = runtime.Runtime.path(
            "{}/tpgt_{}/acls/{}/auth".format(
                self.target, self.tpg, self.acl['initiator']))[0]
        current = {}
        current['userid'] = open(path + "/userid").read().rstrip('\n')
        current['password'] = open(path + "/password").read().rstrip('\n')
        current['userid_mutual'] = open(
            path + "/userid_mutual").read().rstrip('\n')
        current['password_mutual'] = open(
            path + "/password_mutual").read().rstrip('\n')

        if utils.compare_settings(keys, current, self.acl):
            return []

        cmd = ["targetcli",
               "/{}/{}/tpg{}/acls/{}".format(
                   runtime.Runtime.fabric, self.target,
                   self.tpg, self.acl['initiator']),
               "set", "auth",
               "userid={}".format(self.acl['userid']),
               "password={}".format(self.acl['password']),
               "userid_mutual={}".format(self.acl['userid_mutual']),
               "password_mutual={}".format(self.acl['password_mutual'])]
        return cmd

    def set_acls_mode(self):
        """Set the ACL mode.

        Enable authentication, disable acls generation.
        Checks current settings.
        """
        path = runtime.Runtime.path("{}/tpgt_{}/attrib".format(
            self.target, self.tpg))[0]
        authentication = open(path + "/authentication").read().rstrip('\n')
        demo_mode_write_protect = open(
            path + "/demo_mode_write_protect").read().rstrip('\n')
        generate_node_acls = open(
            path + "/generate_node_acls").read().rstrip('\n')

        if (authentication == "1" and
                demo_mode_write_protect == "0" and
                generate_node_acls == "0"):
            return []
        return ["targetcli",
                "/{}/{}/tpg{}".format(
                    runtime.Runtime.fabric, self.target, self.tpg),
                "set", "attribute", "authentication=1",
                "demo_mode_write_protect=0", "generate_node_acls=0"]

    def create(self):
        """Execute all the authentication commands """
        for cmd in self.cmds:
            if cmd:
                utils.popen(cmd)
