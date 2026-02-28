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
    description = "Loads clean ntdll.dll from disk, possibly for syscall/anti-EDR"
    severity = 3
    categories = ["syscall", "anti-edr", "unhooking"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1562.001", "T1055"]  # MITRE v6,7,8

    filter_apinames = set(["NtCreateFile", "NtCreateSection", "NtOpenFile", "NtProtectVirtualMemory", "NtReadFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.filehandle = ""
        self.mapped = False

    def on_call(self, call, process):
        if call["api"] in ["NtCreateFile", "NtOpenFile"]:
            filename = self.get_argument(call, "FileName")
            if filename and filename.lower().endswith(r"\system32\ntdll.dll"):
                filehandle = self.get_argument(call, "FileHandle")
                self.filehandle = filehandle
                self.mark_call()
                self.ret = True

        if call["api"] == ("NtReadFile"):
            filehandle = self.get_argument(call, "FileHandle")
            handlename = self.get_argument(call, "HandleName")
            if self.filehandle and filehandle == self.filehandle and handlename and "ntdll.dll" in handlename.lower():
                self.mark_call()

        if call["api"] == ("NtCreateSection"):
            filehandle = self.get_argument(call, "FileHandle")
            filename = self.get_argument(call, "FileName")
            if filehandle == self.filehandle and "ntdll.dll" in filename.lower():
                self.mapped = True
                self.mark_call()

        if call["api"] == ("NtProtectVirtualMemory"):
            if self.mapped:
                modulename = self.get_argument(call, "ModuleName")
                if modulename and modulename.lower() == "ntdll.dll":
                    protection = self.get_argument(call, "NewAccessProtection")
                    # 0x40 PAGE_EXECUTE_READWRITE, 0x80 PAGE_EXECUTE_WRITECOPY, 0x04 PAGE_READWRITE
                    if protection in ["0x00000040", "0x00000080", "0x00000004"]:
                        self.mark_call()

    def on_complete(self):
        return self.ret


class NtdllMemoryUnhooking(Signature):
    name = "ntdll_memory_unhooking"
    description = "Modifies the memory protection of ntdll.dll to PAGE_READWRITE, indicative of EDR unhooking"
    severity = 3
    confidence = 100
    categories = ["evasion"]
    authors = ["Kevin Ross", "Gemini"]
    minimum = "1.3"
    evented = True
    ttps = ["T1562.001", "T1055"]

    filter_apinames = {"NtProtectVirtualMemory", "VirtualProtectEx", "VirtualProtect"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unhooked_modules = set()

    def on_call(self, call, process):
        module_name = self.get_argument(call, "ModuleName")
        if not module_name:
            return
            
        if "ntdll.dll" in module_name.lower():
            protection = self.get_argument(call, "NewAccessProtection") or self.get_argument(call, "Protection")
            if not protection:
                return
                
            try:
                prot_val = int(protection, 16) if str(protection).startswith("0x") else int(protection)
                
                # 0x04 is PAGE_READWRITE, 0x40 is PAGE_EXECUTE_READWRITE
                if prot_val == 0x04 or prot_val == 0x40:
                    self.unhooked_modules.add(module_name)
                    self.mark_call()
                    self.ret = True
            except ValueError:
                # Fallback: check the pretty_value translated by CAPE
                for arg in call.get("arguments", []):
                    if arg.get("name") in ("NewAccessProtection", "Protection"):
                        pretty_prot = arg.get("pretty_value", "").upper()
                        if "READWRITE" in pretty_prot:
                            self.unhooked_modules.add(module_name)
                            self.mark_call()
                            self.ret = True
                        break

    def on_complete(self):
        if self.ret:
            self.data.append({"unhooked_module": list(self.unhooked_modules)})
        return self.ret
