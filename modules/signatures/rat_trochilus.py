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

class TrochilusRATAPIs(Signature):
    name = "trochilusrat_APIs"
    description = "TrochilusRAT behavior detected"
    severity = 3
    categories = ["RAT"]
    families = ["TrochilusRAT"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["OutputDebugStringW", "CreateProcessInternalW", "RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.score = int()

    def on_call(self, call, process):
        if call["api"] == "OutputDebugStringW":
            outputstr = self.get_argument(call, "OutputString")
            if outputstr:
                if "init servant. server" in outputstr:
                    self.score += 3
        
        if call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine")
            if cmdline:
                if "XLServant" in cmdline:
                    self.score += 2

        if call["api"] == "RegSetValueExW":
            valname = self.get_argument(call, "ValueName")
            fulname = self.get_argument(call, "FullName")
            if valname and valname == "XLServant":
                self.score += 1
            if fulname and fulname.endswith("XLServant"):
                self.score += 1
    
    def on_complete(self):
        if self.score >= 3:
            return True

        return False