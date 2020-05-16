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

class OfficeAddinLoading(Signature):
    name = "office_addinloading"
    description = "Creates add-in (DLL) that automatically loads when launching Word or Excel."
    severity = 3
    categories = ["office", "persistence", "evasion", "execution"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttp = ["T1137"]

    def run(self):
        indicators = [
		".*\\AppData\\Roaming\\Microsoft\\Word\\startup\\*.wll",
		".*\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\*.xll",
		".*\\AppData\\Roaming\\Microsoft\\AddIns\\*.xlam",
		".*\\AppData\\Roaming\\Microsoft\\AddIns\\*.xla"
        ]

        for indicator in indicators:
            match = self.check_file(pattern=indicator)
            if match:
                self.data.append({"file": match})
                return True

        return False 

class OfficePerfKey(Signature):
    name = "office_perfkey"
    description = "Creates registry key for persistence which will automatically load when launching any Office application."
    severity = 3
    categories = ["office", "persistence", "evasion", "execution"]
    authors = ["bartblaze"]
    minimum = "1.3"
	ttp = ["T1137"]

    def run(self):
        indicators = [
            "HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Office test\\\\Special\\\\Perf$"
        ]

        for indicator in indicators:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False 
