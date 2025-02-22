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

class ReadsMemoryRemoteProcess(Signature):
    name = "reads_memory_remote_process"
    description = "Reads from the memory of another process"
    severity = 2
    categories = ["memory scraping", "injection"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["ReadProcessMemory"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    def on_call(self, call, process):
            prochandle = self.get_argument(call, "ProcessHandle")
            if prochandle not in ["0x00000000","0x0000000000000000","0xffffffff","0xffffffffffffffff"]:
                buf = self.get_argument(call, "Buffer")
                if len(buf) > 0:
                    self.mark_call()
                    self.ret = True

    def on_complete(self):
        return self.ret
