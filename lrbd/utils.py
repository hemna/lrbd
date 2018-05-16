
import logging
import netifaces
import re
from subprocess import PIPE
from subprocess import Popen
import time


def popen(cmd):
    """Execute a command.

    print both stdout and stderr, and raise exception
    unless successful.

        cmd - an array of strings of the command
    """
    print(" ".join(cmd))
    proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
    for line in proc.stdout:
        print(line.decode('utf-8').rstrip('\n'))
    for line in proc.stderr:
        print(line.decode('utf-8').rstrip('\n'))
    proc.wait()
    if (proc.returncode != 0):
        raise RuntimeError("command failed", proc.returncode)
    if (logging.getLogger().level <= logging.INFO):
        print()


def retry(cmd, **kwargs):
    """Retry to execute commands for some errors.

    Specifically, error codes such as "95: Operation not supported" may be
    temporary conditions and should be retried.
    Errors such as "2: No such file or directory" is
    likely a typo and need only try once.

        cmd - an array of strings of the command
        retries - number of attempts
        sleep - base seconds to wait
        retry_errors - list of error codes
    """
    retries = int(kwargs.pop('retries', 3))
    sleep = int(kwargs.pop('sleep', 4))
    retry_errors = kwargs.pop('retry_errors', [])

    for attempt in range(1, retries + 1):
        try:
            popen(cmd)
        except RuntimeError as e:
            if (e[1] in retry_errors and attempt < retries):
                wait_time = sleep * attempt
                print("Waiting {} seconds to try again".format(wait_time))
                time.sleep(wait_time)
                continue
            else:
                raise
        # Success
        break


def strip_comments(text):
    """Remove all entries beginning with # to end of line

        text - a string
    """
    return re.sub(re.compile("#.*?\n"), "", text)


def lstrip_spaces(text):
    """Remove 12 spaces

        text - a string
    """
    return re.sub(re.compile("^ {12}", re.MULTILINE), "", text)


def check_keys(keys, data, description):
    """Verify that keys are present in data

        keys - an array of strings
        data - a dict
        description - a string
    """
    for key in keys:
        if key not in data:
            raise ValueError("Missing attribute '{}' in {}".
                             format(key, description))


def compare_settings(keys, current, config):
    """Verify that values are identical

        keys - an array of strings
        current - a dict
        config - a dict, possible superset of current
    """
    for key in keys:
        if current[key] != config[key]:
            return False
    return True


def addresses():
    """Return a list of all ip addresses. """
    adds = []
    for interface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(interface)
        try:
            for entry in addrs[netifaces.AF_INET]:
                adds.append(entry['addr'])
            for entry in addrs[netifaces.AF_INET6]:
                # Strip interface
                adds.append(re.split("%", entry['addr'])[0])
        except KeyError:
            # skip downed interfaces
            pass
    return adds


def uniq(cmds):
    """Remove redundant entries from list of lists."""
    dictionary = {}
    unique = []
    for cmd in cmds:
        dictionary[" ".join(cmd)] = ''
    for k in dictionary.keys():
        unique.append(k.split())
    return sorted(unique)
