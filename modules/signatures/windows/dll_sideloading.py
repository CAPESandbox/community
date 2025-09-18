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

class DLLLoadSuspiciousDirectory(Signature):
    name = "dllload_suspicious_directory"
    description = "A DLL was loaded from a suspicious directory"
    severity = 2
    confidence = 50
    categories = ["side loading"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    enabled = True
    ttps = ["T1574"]  # MITRE v6,7,8
    mbcs = ["F0015"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        # Any exclusions added to this list needs to be in lower format.
        self.ignore_directories = [
            "c:\\windows\\system32\\",
            "c:\\windows\\syswow64\\",
            "c:\\windows\\",
            "c:\\windows\\winsxs\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
            "c:\\programdata\\",
        ]

    filter_apinames = set(["DllLoadNotification"])

    def on_call(self, call, process):
        if not call["status"]:
            return None

        if call["api"] == "DllLoadNotification":
            notificationreason = self.get_argument(call, "NotificationReason")
            dllname = self.get_argument(call, "DllName")
            if notificationreason == "load":
                pname = process["process_name"].lower()
                dllnamelower = dllname.lower()
                is_ignored = any(dllnamelower.startswith(d) for d in self.ignore_directories)
                if not is_ignored:
                    self.mark_call()
                    self.data.append({"suspicious_dll_load": "Process %s loaded a DLL from a suspicious directory, this is possibly indicative of DLL side loading/search order hijacking" % (pname)})
                    self.ret = True

    def on_complete(self):
        return self.ret
