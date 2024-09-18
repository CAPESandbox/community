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


class ThreadManipulationRemoteProcess(Signature):
    name = "resumethread_remote_process"
    description = "Resumed a thread in another process"
    severity = 2
    categories = ["injection", "unpacking"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]  # MITRE v6,7,8

    filter_apinames = set(["NtResumeThread"])
    whitelist = [
        "svchost.exe",
        "services.exe",
        "acrobat.exe",
        "explorer.exe",
        "microsoftedgeupdate.exe",
        "werfault.exe",
        "taskhostw.exe",
        "mousocoreworker.exe",
        "adobecollabsync.exe",
        "trustedinstaller.exe",
        "adobe crash processor.exe",
        "acrocef.exe",
    ]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.sourcepid = []
        self.targetpid = []

    def on_call(self, call, process):
        procid = self.get_argument(call, "ProcessId")
        processid = process["process_id"]
        if procid != processid:
            if processid not in self.sourcepid and procid not in self.targetpid:
                pname = process["process_name"].lower()
                if pname.lower() not in self.whitelist:
                    self.sourcepid.append(processid)
                    self.targetpid.append(procid)
                    self.data.append(
                        {
                            "thread_resumed": "Process %s with process ID %s resumed a thread in another process with the process ID %s"
                            % (pname, processid, procid)
                        }
                    )
                    self.mark_call()
                    self.ret = True

    def on_complete(self):
        return self.ret
