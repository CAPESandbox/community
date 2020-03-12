# Copyright (C) 2019 ditekshen
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

class GermanWiperMutexes(Signature):
    name = "germanwiper_mutexes"
    description = "Creates known GermanWiper ransomware mutexes"
    severity = 3
    categories = ["ransomware"]
    families = ["GermanWiper"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        indicators = [
                "cFgxTERNWEVhM2V$",
                "HSDFSD-HFSD-3241-91E7-ASDGSDGHH$",
        ]

        for indicator in indicators:
            match_mutex = self.check_mutex(pattern=indicator, regex=True)
            if match_mutex:
                self.data.append({"mutex": match_mutex})
                return True

        return False
