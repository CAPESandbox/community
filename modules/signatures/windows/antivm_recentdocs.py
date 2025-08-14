# Copyright (C) 2025 bartblaze
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


class RecentDocsDetect(Signature):
    name = "antivm_recentdocs"
    description = "Queries the RecentDocs registry key."
    severity = 1
    categories = ["discovery"]
    authors = ["bartblaze"]
    minimum = "0.5"
    evented = True
    ttps = ["T1012"]
    reference = ["https://unit42.paloaltonetworks.com/snipbot-romcom-malware-variant/"]

    def run(self):
        return self.check_key(pattern=r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")
