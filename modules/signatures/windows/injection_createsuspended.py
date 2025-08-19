# Copyright (C) 2025 Kevin Ross
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

class CreatesSuspendedProcess(Signature):
    name = "creates_suspended_process"
    description = "Creates a process in a suspended state, likely for injection"
    severity = 2
    confidence = 50
    categories = ["injection", "process hollowing"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True
    ttps = ["T1055"]  # MITRE v6,7,8

    filter_apinames = set(["CreateProcessInternalA", "CreateProcessInternalW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    def on_call(self, call, process):
        if call["api"].startswith("CreateProcessInternal"):
            flags = int(self.get_argument(call, "CreationFlags"), 16)
            if flags & 0x4:
                self.mark_call()
                self.ret = True
                
    def on_complete(self):
        return self.ret
