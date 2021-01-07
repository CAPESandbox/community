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

class DisablesAutomaticAppTermination(Signature):
    name = "disables_auto_app_termination"
    description = "Disables automatic termination of applications that block or cancel shutdown"
    severity = 2
    categories = ["ransomware"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    def run(self):    
        indicators = [
            "HKEY_LOCAL_MACHINE\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\System\\\\AllowBlockingAppsAtShutdown",
        ]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False