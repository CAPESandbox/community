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

from lib.cuckoo.common.abstracts import Signature


class PersistenceRDPRegistry(Signature):
    name = "persistence_rdp_registry"
    description = "Modifies Terminal Server registry keys for persistence"
    severity = 3
    categories = ["persistence"]
    authors = ["bartblaze"]
    minimum = "1.2"
    evented = True
    ttp = ["T1021"]

    def run(self):
        ret = False
        reg_indicators = [
            ".*\\\\Control\\\\Terminal Server\\\\fSingleSessionPerUser$",
            ".*\\\\Control\\\\Terminal Server\\\\fDenyTSConnections$",
            ".*\\\\Control\\\\Terminal Server\\\\fAllowToGetHelp$",
        ]

        for indicator in reg_indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                ret = True
                self.data.append({"regkey": match})

        return ret


class PersistenceRDPShadowing(Signature):
    name = "persistence_rdp_shadowing"
    description = "Writes to the Terminal Server registry set, potentially for RDP shadowing and persistence."
    severity = 3
    categories = ["persistence"]
    authors = ["bartblaze"]
    minimum = "1.2"
    evented = True
    ttp = ["T1021"]
    reference = ["https://bitsadm.in/blog/spying-on-users-using-rdp-shadowing"]

    def run(self):
        ret = False
        reg_indicators = [
            ".*\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows NT\\\\Terminal Services$",
        ]

        for indicator in reg_indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                ret = True
                self.data.append({"regkey": match})

        return ret
