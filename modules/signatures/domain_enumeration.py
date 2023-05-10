# Copyright (C) 2023 Kevin Ross
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


class DomainEnumerationCommands(Signature):
    name = "domain_enumeration_commands"
    description = "Attempts to enumerate domain controller/domain information"
    severity = 3
    confidence = 100
    categories = ["lateral", "domain"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1482"]

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()

            if "nltest" in lower and (
                "domain_trusts" in lower or "all_trusts" in lower or "trusted_domains" in lower or "dclist" in lower
            ):
                ret = True
                self.data.append({"command": cmdline})

            if "dsquery" in lower:
                ret = True
                self.data.append({"command": cmdline})

            if "net" in lower and "domain" in lower and ("view" in lower or "groups" in lower):
                ret = True
                self.data.append({"command": cmdline})

        return ret
