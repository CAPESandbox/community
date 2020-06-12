# Copyright (C) 2020 ditekshen
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

class PersistenceIFEO(Signature):
    name = "persistence_ifeo"
    description = "Modifies Image File Execution Options, indicative of process injection or persistence"
    severity = 3
    categories = ["persistence", "injection", "evasion", "escalation"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1183"]
    evented = True

    def run(self):
        indicators = [
            "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\Image\sFile\sExecution\sOptions\\\\.*",
        ]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False


class PersistenceSilentProcessExit(Signature):
    name = "persistence_slient_process_exit"
    description = "Modifies Slient Process Exit Options, indicative of process injection or persistence"
    severity = 3
    categories = ["persistence", "injection", "evasion", "escalation"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1183"]
    evented = True

    def run(self):
        indicators = [
            "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\SilentProcessExit\\\\.*",
        ]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False