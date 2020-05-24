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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class MassLoggerFiles(Signature):
    name = "masslogger_files"
    description = "Creates MassLogger infostealer files"
    severity = 3
    categories = ["infostealer"]
    families = ["MassLogger"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    def run(self):
        user = self.get_environ_entry(self.get_initial_process(), "UserName")
        indicators = [
            ".*\\\\AppData\\\\Local\\\\Temp\\\\[A-F0-9]{10}\\\\Log\.txt$",
            ".*\\\\AppData\\\\Local\\\\Temp\\\\[A-F0-9]{10}\\\\Screenshot\.jpeg$",
            ".*\\\\AppData\\\\Local\\\\Temp\\\\[A-F0-9]{10}\\\\DotNetZip-.*\.tmp$",
        ]
        score = 0

        indicators.append(".*\\\\AppData\\\\Local\\\\Temp\\\\[A-F0-9]{10}\\\\" + user + "_.*_[A-F0-9]{10}_\d{2}-\d{2}-\d{4}\s.*.zip")

        for indicator in indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                score += 1
                self.data.append({"file": match})
        
        if score >= 3:
            return True

        return False