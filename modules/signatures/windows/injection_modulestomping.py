# Copyright (C) 2026 Kevin Ross
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


class InjectionModuleStompingProbing(Signature):
    name = "injection_module_stomping_probing"
    description = "Executes loops of failed RWX memory allocations returning CONFLICTING_ADDRESSES in high-memory ranges, indicative of code cave hunting or module stomping"
    severity = 3
    confidence = 30
    categories = ["evasion", "injection", "stealth"]
    authors = ["Kevin Ross", "Gemini"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]

    filter_apinames = {"NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.failed_allocations = {}
        self.marked_count = 0

    def on_call(self, call, process):
        pid = process.get("process_id")
        proc_name = process.get("process_name", "unknown")

        call_status = call.get("status", True)
        call_return = str(call.get("return", "")).lower()

        # 0xffffffffc0000018 is STATUS_CONFLICTING_ADDRESSES
        if not call_status or "c0000018" in call_return:
            protection = self.get_argument(call, "Protection") or self.get_argument(call, "flProtect")

            if protection:
                try:
                    prot_val = int(protection, 16) if isinstance(protection, str) else protection

                    # 0x40 is PAGE_EXECUTE_READWRITE (RWX)
                    if prot_val == 0x40:

                        if pid not in self.failed_allocations:
                            self.failed_allocations[pid] = {"proc_name": proc_name, "count": 0}

                        self.failed_allocations[pid]["count"] += 1
                        if self.marked_count < 20:
                            self.mark_call()
                            self.marked_count += 1
                            self.ret = True

                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            formatted_results = []

            for pid, data in self.failed_allocations.items():
                count = data["count"]
                proc_name = data["proc_name"]

                if count > 5:
                    formatted_results.append(f"pid {pid} process {proc_name} executed {count} probes")

            if formatted_results:
                self.data.append({"rwx_probing_loops_detected": formatted_results})
                return True

        return False
