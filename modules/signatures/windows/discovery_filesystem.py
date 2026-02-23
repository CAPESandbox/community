# Copyright (C) 2026 Kevin Ross
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

class FolderEnumeration(Signature):
    name = "folder_enumeration"
    description = "Systematically searches multiple user directories using wildcards, common in ransomware/wipers/infostealers"
    severity = 3
    confidence = 70
    categories = ["ransomware", "wiper", "infostealer", "discovery"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    enabled = True
    ttps = ["T1083"]
    mbcs = ["B0002.001"]

    def run(self):
        targeted_folders = set()
        pattern = r".*(Users|Documents|Desktop|Downloads|Music|Videos|Pictures|AppData).*\\\*.*"      
        matches = self.check_file(pattern=pattern, regex=True, all=True)
        
        if matches:
            for match in matches:
                folder = match.rsplit('\\', 1)[0].lower()
                if folder not in targeted_folders:
                    targeted_folders.add(folder)
                    self.data.append({"target_folder": match})

        if len(targeted_folders) > 10:
            return True

        return False
