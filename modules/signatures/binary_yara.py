# Copyright (C) 2023 Eye Security (yasin.tas@eye.security)
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

class BinaryTriggeredYARA(Signature):
    name = "binary_yara"
    description = "Binary file triggered YARA rule"
    severity = 3
    confidence = 80
    weight = 1
    categories = ["static"]
    authors = ["Yasin Tas",  "Eye Security"]
    minimum = "1.3"

    def run(self):
        count = 0

        yara_triggered = self.results["target"]["file"]["yara"]
        if yara_triggered != []:
            for yara in yara_triggered:
                self.data.append({"Binary triggered YARA rule": yara["name"]})
                count += 1
            if count > 1:
                self.description = "Binary file triggered multiple YARA rules"
            if count > 3:
                self.weight = 3
            return True
        return False