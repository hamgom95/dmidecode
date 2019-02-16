import subprocess
from collections import UserDict
from functools import lru_cache

def _parse_handle_section(lines):
    """
    Parse a section of dmidecode output
    * 1st line contains address, type and size
    * 2nd line is title
    * line started with one tab is one option and its value
    * line started with two tabs is a member of list
    """
    data = {"_title": next(lines).rstrip()}

    for line in lines:
        line = line.rstrip()
        if line.startswith("\t\t"):
            try:
                data[k].append(line.lstrip())
            except AttributeError:
                # ignore stray <OUT OF SPEC> lines
                pass
        elif line.startswith("\t"):
            k, v = [i.strip() for i in line.lstrip().split(":", 1)]
            if v is "":
                data[k] = []
            else:
                data[k] = v
        else:
            break

    return data


class Dmidecode(UserDict):
    """Dmidecode parser storing parsed data as dict like object."""

    TYPE = {
        0: "bios",
        1: "system",
        2: "base board",
        3: "chassis",
        4: "processor",
        7: "cache",
        8: "port connector",
        9: "system slot",
        10: "on board device",
        11: "OEM strings",
        # 13: 'bios language',
        15: "system event log",
        16: "physical memory array",
        17: "memory device",
        19: "memory array mapped address",
        24: "hardware security",
        25: "system power controls",
        27: "cooling device",
        32: "system boot",
        41: "onboard device",
    }

    @classmethod
    def from_command(cls, args=None):
        args = [] if args is None else args
        output = subprocess.run_command(["dmidecode", *args], root=True).stdout
        return cls(output)

    def __init__(self, output):
        self.output = output

    def i_entries(self):
        lines = self.output.strip().splitlines()
        for line in lines:
            if line.startswith("Handle 0x"):
                handle_str, type_str, byte_str = line.split(",", 2)
                handle = handle_str.split(" ", 1)[1]
                typ = int(type_str.strip()[len("DMI type") :])
                if typ in cls.TYPE:
                    # parse section
                    section = _parse_handle_section(lines)

                    # add handle information
                    entry = {**section, "Handle": handle}

                    yield (cls.TYPE[typ], entry)

    @property
    @lru_cache
    def entries(self):
        return list(self.i_entries())

    @property
    @lru_cache
    def categories(self):
        """Parse dmidecode output to dict of categories with subitems.
        """
        d = {}
        for category, entry in self.entries:
            # gather entries in categories
            d.setdefault(category, []).append(entry)
        return d
