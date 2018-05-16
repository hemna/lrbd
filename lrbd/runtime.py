
import glob


class Runtime(object):
    """Sharing common runtime state.  """
    config = {}
    target = "/sys/kernel/config/target"
    fabric = "iscsi"

    @staticmethod
    def tpg(*args):
        """Get target portal group.

        Returns target portal group for specified target and entry if portal
        exists, otherwise defaults to 1. Also returns the target portal group
        for specified target, image and portal.
        """
        target = args[0]
        if len(args) == 2:
            entry = args[1]
            if 'portal' in entry:
                return (Runtime.config['portals'][target][entry['image']]
                        [entry['portal']])
            else:
                return 1
        else:
            image = args[1]
            portal = args[2]
            return Runtime.config['portals'][target][image][portal]

    @staticmethod
    def core(pathname):
        """Returns composed core path """
        return glob.glob("{}/{}/{}".format(Runtime.target, "core", pathname))

    @staticmethod
    def path(pathname):
        """Returns composed path """
        return glob.glob("{}/{}/{}".format(Runtime.target,
                                           Runtime.fabric,
                                           pathname))

    @staticmethod
    def targets():
        """Returns targets """
        return Runtime.config['portals'].keys()

    @staticmethod
    def images(target):
        """Returns images """
        return Runtime.config['portals'][target].keys()

    @staticmethod
    def portals(target, image):
        """Returns portals """
        return Runtime.config['portals'][target][image].keys()

    @staticmethod
    def backstore(pool, entry):
        if 'rbd_name' in entry and entry['rbd_name'] == "simple":
            name = entry['image']
        else:
            name = "-".join([pool, entry['image']])
        return(name)
