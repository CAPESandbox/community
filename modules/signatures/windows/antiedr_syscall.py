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


class Suspicious_NTDLL_DiskLoad(Signature):
    name = "suspicious_ntdll_disk_load"
    description = "Loads clean ntdll.dll from disk (possibly for syscall/anti-EDR)"
    severity = 3
    categories = ["syscall", "anti-edr", "unhooking"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1106"]  # MITRE v6,7,8

    filter_apinames = set(["NtCreateFile", "NtCreateSection", "NtOpenFile", "NtProtectVirtualMemory", "NtReadFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.filehandle = ""
        self.mapped = False

    def on_call(self, call, process):
        if call["api"] in ["NtCreateFile", "NtOpenFile"]:
            filename = self.get_argument(call, "FileName")
            if filename.lower() == "c:\windows\system32\ntdll.dll":
                filehandle = self.get_argument(call, "FileHandle")
                self.filehandle == filehandle
                self.mark_call()
                self.ret = True

        if call["api"] == ("NtReadFile"):
            filehandle = self.get_argument(call, "FileHandle")
            handlename = self.get_argument(call, "HandleName")
            if filehandle == self.filehandle and "ntdll.dll" in handlename.lower():
                self.mark_call()

        if call["api"] == ("NtCreateSection"):
             filehandle = self.get_argument(call, "FileHandle")
             filename = self.get_argument(call, "FileName")
             if filehandle == self.filehandle and "ntdll.dll" in filename.lower:
                 self.mapped = True
                 self.mark_call()

        if call["api"] == ("NtProtectVirtualMemory"):
            if self.mapped:
                modulename = self.get_argument(call, "ModuleName")
                if modulename.lower == "ntdll.dll":
                    protection = self.get_argument(call, "NewAccessProtection")
                    # 0x40 PAGE_EXECUTE_READWRITE, 0x80 PAGE_EXECUTE_WRITECOPY, 0x04 PAGE_READWRITE
                    if protection in ["0x00000040", "0x00000080", "0x00000004"]:
                        self.mark_call()

    def on_complete(self):
        return self.ret
