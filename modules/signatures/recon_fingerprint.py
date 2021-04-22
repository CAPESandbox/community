# Copyright (C) 2012,2015 Claudio "nex" Guarnieri (@botherder), Optiv, Inc. (brad.spengler@optiv.com)
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

class Fingerprint(Signature):
    name = "recon_fingerprint"
    description = "Collects information to fingerprint the system"
    severity = 3
    confidence = 75
    categories = ["recon"]
    authors = ["nex", "Optiv"]
    minimum = "1.2"
    ttp = ["T1082"]

    def run(self):
        indicators = [
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\DigitalProductId$",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\ProductId$",
            ".*\\\\Microsoft\\\\Internet\\ Explorer\\\\Registration\\\\ProductId$",
            ".*\\\\Microsoft\\\\Cryptography\\\\MachineGuid$",
            ".*\\\\HARDWARE\\\\DESCRIPTION\\\\System\\\\SystemBIOSDate$",
        ]

        for indicator in indicators:
            match = self.check_read_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True
 
        return False
