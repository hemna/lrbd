#!/usr/bin/python
# Copyright (C) 2015 Eric Jackson <ejackson@suse.com>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see
# <http://www.gnu.org/licenses/>.


from __future__ import print_function
import argparse
import logging
import os
import os.path
import re
import socket
import sys

from lrbd import content
from lrbd import host


parser = argparse.ArgumentParser()


parser.add_argument('-e', '--edit', action='store_true', dest='edit',
                    default=False,
                    help='edit the rbd configuration for iSCSI')
parser.add_argument('-E', '--editor', action='store', dest='editor',
                    help='use editor to edit the rbd configuration for iSCSI',
                    metavar='editor')
parser.add_argument('-c', '--config', action='store', dest='config',
                    help='use name for object, defaults to "lrbd.conf"',
                    metavar='name')
parser.add_argument('--ceph', action='store', dest='ceph',
                    help='specify the ceph configuration file', metavar='ceph')
parser.add_argument('-H', '--host', action='store', dest='host',
                    help='specify the hostname, defaults to either '
                    '"{}" or "{}"'.
                    format(socket.gethostname(), socket.getfqdn()),
                    metavar='host')
parser.add_argument('-n', '--name', action='store', dest='name',
                    help='specify the client name for Ceph authentication, '
                    'defaults to "client.admin"',
                    metavar='name')
parser.add_argument('-p', '--pools', nargs='+', action='store', dest='pools',
                    help='specify a pool list (space separated)',
                    metavar='pools')
parser.add_argument('-o', '--output', action='store_true', dest='output',
                    help='display the configuration')
parser.add_argument('-l', '--local', action='store_true', dest='local',
                    help='display the host configuration')
parser.add_argument('-f', '--file', action='store', dest='file',
                    help='import the configuration from file', metavar='file')
parser.add_argument('-a', '--add', action='store', dest='add',
                    help='add the configuration from file', metavar='file')
parser.add_argument('-u', '--unmap', action='store_true', dest='unmap',
                    help='unmap the rbd images')
parser.add_argument('-v', '--verbose', action='store_true', dest='verbose',
                    help='print INFO messages')
parser.add_argument('-d', '--debug', action='store_true', dest='debug',
                    help='print DEBUG messages')
parser.add_argument('-m', '--migrate', action='store', dest='migrate',
                    help='output migrated configuration', metavar='version')
parser.add_argument('-I', '--iblock', action='store_const',
                    dest='backstore', const='iblock',
                    help='set the backstore to iblock, defaults to rbd')
parser.add_argument('-R', '--rbd', action='store_const', dest='backstore',
                    const='rbd',
                    help='set the backstore to rbd')
parser.add_argument('-W', '--wipe', action='store_true', dest='wipe',
                    help='wipe the configuration objects from all pools')
parser.add_argument('-C', '--clear', action='store_true', dest='clear',
                    help='clear the targetcli configuration')


def disable_check():
    filename = "/var/lib/misc/lrbd.disabled"
    if os.path.isfile(filename):
        upgrade_instructions = open(filename).read().rstrip('\n')
        raise RuntimeError(
            "lrbd has been intentionally disabled by an upgrade.\n\n" +
            upgrade_instructions)


def sysconfig_options(filename="/etc/sysconfig/lrbd"):
    """Return any provided options """
    if os.path.isfile(filename):
        with open(filename) as options:
            for line in options:
                if 'LRBD_OPTIONS' in line:
                    options = re.split(r'[\'="]', line)
                    return options[2].split()
    return []


def main(args=None):
    """LRDB main app.

    Apply stored configuration by default.
    Otherwise, execute the alternate
    path from the specified options.

        args - expects parse_args() result from argparse
    """
    sys.argv.extend(sysconfig_options())
    if args is None:
        args = parser.parse_args()

    if args.editor is not None:
        args.edit = True

    disable_check()

    configs = content.Configs(args.config, args.ceph, args.host, args.name,
                              args.pools)
    logging.basicConfig(format='%(levelname)s: %(message)s')

    if args.verbose or args.wipe or args.host:
        logging.getLogger().level = logging.INFO

    if args.debug:
        logging.getLogger().level = logging.DEBUG

    logging.info("Executing {}".format(" ".join(sys.argv)))

    if args.wipe:
        configs.wipe(content.Cluster())
    elif args.clear:
        try:
            configs.clear()
        except RuntimeError:
            # Kernel modules are already unloaded
            pass
        if args.unmap:
            images = host.Images()
            images.unmap()
    elif args.unmap:
        images = host.Images()
        images.unmap()
    elif args.file:
        conn = content.Cluster()
        contents = content.Content()
        contents.read(args.file)
        configs.wipe(conn)
        contents.save(conn)
    elif args.add:
        contents = content.Content()
        contents.read(args.add)
        contents.save(content.Cluster())
    else:
        sections = {"pools": content.Pools(),
                    "portals": content.PortalSection(),
                    "targets": content.Targets(),
                    "authentications": content.Authentications()}
        gateways = content.Gateways(sections)
        if args.output:
            configs.retrieve(content.Cluster(), sections, gateways)
            configs.display()
        elif args.migrate:
            configs.retrieve(content.Cluster(), sections, gateways)
            configs.migrate(args.migrate)
            configs.display()
        elif args.edit:
            conn = content.Cluster()
            configs.retrieve(conn, sections, gateways)
            contents = content.Content()
            contents.edit(args.editor)
            contents.save(conn)
        elif args.local:
            gateways.hostonly()
            configs.retrieve(content.Cluster(), sections, gateways)
            configs.display()
        else:
            gateways.hostonly()
            configs.retrieve(content.Cluster(), sections, gateways)
            images = host.Images()
            images.map()
            backstores = host.Backstores(args.backstore)
            backstores.create()
            backstore_attrs = host.BackstoreAttributes()
            backstore_attrs.assign()
            iscsi = host.Iscsi()
            iscsi.create()
            lun_assignment = host.LunAssignment()
            tpgs = host.TPGs(host.TPGCounter(),
                             host.PortalIndex(), lun_assignment)
            tpgs.create()
            tpgs.disable_all()
            tpg_attrs = host.TPGattributes()
            tpg_attrs.assign()
            luns = host.Luns(lun_assignment)
            luns.create()
            portals = host.Portals()
            portals.create()
            acls = host.Acls()
            acls.create()
            maps = host.Map()
            maps.map()
            auth = host.Auth()
            auth.create()
            tpgs.enable_local()


# Main
if __name__ == "__main__":
    main()
