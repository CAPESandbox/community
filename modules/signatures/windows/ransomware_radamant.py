# Copyright (C) 2016 Kevin Ross
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


class RansomwareRadamant(Signature):
    name = "ransomware_radamant"
    description = "Exhibits behavior characteristic of Radamant ransomware"
    severity = 3
    families = ["Radamant"]
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    ttps = ["T1486"]  # MITRE v6,7,8
    mbcs = ["OB0008", "E1486"]

    def run(self):
        mutexes = [
            "Radamant_v.*",
            ".*radamantv.*",
        ]

        for mutex in mutexes:
            if self.check_mutex(pattern=mutex, regex=True):
                self.mbcs += ["OC0003", "C0042"]  # micro-behaviour
                return True

        # Check for creation of Autorun
        if self.check_write_key(
            pattern=r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\(svchost|DirectX)$",
            regex=True,
        ) and self.check_write_file(pattern=r".*\\Windows\\dirextx.exe$", regex=True):
            self.ttps += ["T1112"]  # MITRE v6,7,8
            self.mbcs += ["E1112"]
            self.mbcs += ["OC0008", "C0036"]  # micro-behaviour
            return True

        # Check for creation of ransom message file
        if self.check_write_file(pattern=r".*\\YOUR_FILES.url$", regex=True):
            self.mbcs += ["OC0001", "C0016"]  # micro-behaviour
            return True

        return False
