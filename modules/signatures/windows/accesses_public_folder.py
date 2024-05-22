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


class AccessesPublicFolder(Signature):
    name = "accesses_public_folder"
    description = "A file was accessed within the Public folder."
    severity = 1
    categories = ["generic"]
    authors = ["@CybercentreCanada"]
    minimum = "1.2"
    ttps = ["T1548", "T1078", "T1036"]
    mbcs = []
    evented = True
    confidence = 10

    def run(self):
        file_indicator = "C:\\\\Users\\\\Public\\\\.*"
        found = False
        file_match = self.check_file(pattern=file_indicator, regex=True, all=True)
        if file_match:
            for match in file_match:
                self.data.append({"file": match})
            found = True
        return found
