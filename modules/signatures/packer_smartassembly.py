# Copyright (C) 2015 KillerInstinct
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

class SmartAssemblyPacked(Signature):
    name = "packer_smartassembly"
    description = ".NET file is packed/obfuscated with SmartAssembly"
    severity = 2
    categories = ["packer"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    ttp = ["T1045"]

    def run(self):
        if not "static" in self.results or not "dotnet" in self.results["static"]:
            return False

        if "customattrs" in self.results["static"]["dotnet"] and self.results["static"]["dotnet"]["customattrs"]:
            for attr in self.results["static"]["dotnet"]["customattrs"]:
                if "smartassembly" in attr["value"].lower():
                    return True

        return False
