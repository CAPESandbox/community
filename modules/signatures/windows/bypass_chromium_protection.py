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


class BypassChromiumProtection(Signature):
    name = "bypass_chromium_protection"
    description = "Attempts to bypass Chromium's cookie data protection"
    severity = 2
    categories = ["evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    reference = ["https://www.elastic.co/security-labs/katz-and-mouse-game"]

    def run(self):
        for cmdline in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            lower = cmdline.lower()
            if "--remote-allow-origins" in lower or "--remote-debugging-port" in lower:
                self.data.append({"command": cmdline})
                return True

        return False
