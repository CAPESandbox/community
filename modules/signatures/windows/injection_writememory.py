# Copyright (C) 2024 Kevin Ross
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

class InjectionWriteRemoteProcess(Signature):
    name = "injection_write_process"
    description = "Writes to the memory another process"
    severity = 2
    categories = ["injection", "unpacking"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]  # MITRE v6,7,8

    filter_apinames = set(["NtWow64WriteVirtualMemory64", "WriteProcessMemory"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.sourcepids = []
        self.targethandles = []

    def on_call(self, call, process):
            prochandle = self.get_argument(call, "ProcessHandle")
            if prochandle not in ("0x00000000","0x0000000000000000","0xffffffff","0xffffffffffffffff"):
                pname = process["process_name"].lower()
                processid = process["process_id"]
                if processid not in self.sourcepids and prochandle not in self.targethandles:
                    self.data.append({"write_memory": "Process %s with process ID %s wrote to the memory of process handle %s" % (pname, processid, prochandle)})
                    self.sourcepids.append(processid)
                    self.targethandles.append(prochandle)
                self.mark_call()
                self.ret = True

    def on_complete(self):
        return self.ret

class InjectionWriteEXEProcess(Signature):
    name = "injection_write_exe_process"
    description = "Writes an executable to the memory of another process"
    severity = 3
    categories = ["injection", "unpacking"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]  # MITRE v6,7,8

    filter_apinames = set(["NtWow64WriteVirtualMemory64", "WriteProcessMemory"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.handles = []
        self.sourcepids = []
        self.targethandles = []

    def on_call(self, call, process):
            prochandle = self.get_argument(call, "ProcessHandle")
            if prochandle not in ("0x00000000","0x0000000000000000","0xffffffff","0xffffffffffffffff"):
                if self.get_argument(call, "Buffer").startswith("MZ") or prochandle in self.handles:
                    pname = process["process_name"].lower()
                    processid = process["process_id"]
                    if prochandle not in self.handles:
                        self.handles.append(prochandle)
                    if processid not in self.sourcepids and prochandle not in self.targethandles:
                        self.data.append({"write_exe_memory": "Process %s with process ID %s wrote an executable to the process handle %s" % (pname, processid, prochandle)})
                        self.sourcepids.append(processid)
                        self.targethandles.append(prochandle)
                    self.mark_call()
                    self.ret = True

    def on_complete(self):
        return self.ret
