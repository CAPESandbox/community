# Copyright (C) 2026 Kevin Ross, detection logic refined with Gemini
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

class SyscallEvasion(Signature):
    name = "syscall_evasion"
    description = "Executes direct syscalls to evade EDR and user-land API hooks"
    severity = 3
    confidence = 80
    categories = ["evasion", "stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]

    filter_apinames = {"sysenter"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.evasive_syscalls = set()

    def on_call(self, call, process):
        ret_addr = self.get_argument(call, "Return Address")
        
        if not ret_addr or ret_addr == "0x00000000":
            return
            
        try:
            addr_val = int(ret_addr, 16) if ret_addr.startswith("0x") else int(ret_addr)
             
            # System DLLs (ntdll.dll, kernel32.dll) load very high in memory.
            # 32-bit: > 0x70000000 | 64-bit: > 0x7FF000000000
            # If the literal Return Address is in low memory, the malware is 
            # manually executing the syscall (Direct) or jumping to it (Indirect).
            is_evasive = False
            if 0 < addr_val < 0x70000000:
                is_evasive = True
            elif 0x0000000100000000 <= addr_val < 0x0000700000000000:
                is_evasive = True

            module = self.get_argument(call, "Module")
            if module:
                module_lower = module.lower()
                safe_modules = ["kernel32", "kernelbase", "ntdll", "wow64"]
                if any(safe in module_lower for safe in safe_modules) and not is_evasive:
                    return

            if is_evasive:
                mod_name = module if module else "Unknown_Memory"
                if mod_name not in self.evasive_syscalls:
                    self.evasive_syscalls.add(mod_name)
                    if len(self.evasive_syscalls) <= 10:
                        self.mark_call()

        except ValueError:
            pass

    def on_complete(self):
        ret = False
        if len(self.evasive_syscalls) > 0:
            self.data.append({"evasive_syscall_modules": list(self.evasive_syscalls)})
            ret = True

        return ret
