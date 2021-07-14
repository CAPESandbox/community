# Copyright (C) 2020 bartblaze
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class UsesRemoteDesktopSession(Signature):
    name = "uses_remote_desktop_session"
    description = "Connects to/from or queries a remote desktop session"
    severity = 3
    categories = ["access"]
    authors = ["bartblaze"]
    minimum = "1.2"
    ttp = ["T1021"]
    evented = True

    def run(self):
        utilities = [
            "tscon ",
            "tscon.exe",
            "mstsc ",
            "mstsc.exe",
            "qwinsta ",
            "qwinsta.exe",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class UsesRDPClip(Signature):
    name = "uses_rdp_clip"
    description = "Accesses the RDP Clip Monitor (RDP clipboard)"
    severity = 3
    categories = ["access"]
    authors = ["bartblaze"]
    minimum = "1.2"
    ttp = ["T1021"]
    evented = True

    def run(self):
        utilities = [
            "rdpclip ",
            "rdpclip.exe"
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class RDPTCPKey(Signature):
    name = "rdptcp_key"
    description = "Writes to the RDP-Tcp registry key related to Remote Desktop."
    severity = 3
    categories = ["persistence", "evasion", "execution"]
    authors = ["bartblaze"]
    minimum = "1.3"
    ttp = ["T1137"]

    def run(self):
        indicators = [
            ".*\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\WinStations\\\\RDP-Tcp"
        ]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False
