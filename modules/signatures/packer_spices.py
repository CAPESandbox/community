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

class SpicesPacked(Signature):
    name = "packer_spices"
    description = ".NET executable is packed/obfuscated with 9Rays.Net Spices.Net Obfuscator"
    severity = 2
    categories = ["packer"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1045"]

    def run(self):
        for attr in self.results.get("static", {}).get("dotnet", {}).get("customattrs", []):
            if "9rays.net" in attr["value"].lower() or "spices.net" in attr["value"].lower():
                return True

        return False
