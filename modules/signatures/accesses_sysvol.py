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

class AccessesSysvol(Signature):
    name = "accesses_sysvol"
    description = "Accesses or reads files from the SYSVOL folder, possibly to dump passwords"
    severity = 3
    categories = ["credential_access"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttp = ["T1552"]	

    def run(self):
        indicators = [
            "C:\\\\Windows\\\\SYSVOL\\\\.*",
        ]

        for indicator in indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False
