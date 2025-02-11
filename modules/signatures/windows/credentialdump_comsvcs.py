# Copyright (C) 2024 Kevin Ross
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

from lib.cuckoo.common.abstracts import Signature


class ComsvcsCredentialDump(Signature):
    name = "comsvcs_credentialdump"
    description = "Dumps process memory using comsvcs (likely credential dump of LSASS process)"
    severity = 3
    categories = ["credentials"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1003"]  # # MITRE v6,7,8
    reference = [
        "www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz"
    ]

    def run(self):
        ret = False
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "comsvcs" in lower and "minidump" in lower:
                ret = True
                self.data.append({"command": cmdline})

        return ret
