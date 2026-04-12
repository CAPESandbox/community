# Copyright (C) 2026 Kevin Ross, created with assistance from Gemini
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

class UnbackedExceptionFilter(Signature):
    name = "unbacked_exception_filter"
    description = "Altered the unhandled exception filter from dynamically allocated (unbacked) memory, indicative of fileless anti-debugging or silent crash suppression"
    severity = 3
    confidence = 100
    categories = ["defense_evasion", "anti_debugging", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1622", "T1562"]

    filter_apinames = {
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "SetUnhandledExceptionFilter", "RtlAddVectoredExceptionHandler"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.exception_events = set()

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "RegionSize") or self.get_argument(call, "dwSize")
            
            if base_address and region_size:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                    
                    if pid not in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = []
                    self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass

        elif api in ("SetUnhandledExceptionFilter", "RtlAddVectoredExceptionHandler"):
            caller_addr = call.get("caller")
            
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            proc_name = process.get("process_name", "unknown")
                            
                            event_msg = f"{proc_name} modified exception filters ({api}) from unbacked caller {caller_addr}"
                            if event_msg not in self.exception_events:
                                self.exception_events.add(event_msg)
                                self.mark_call()
                                self.ret = True
                            break
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_exception_filters": list(self.exception_events)})
        return self.ret
        

class UnbackedProcessMitigationAlteration(Signature):
    name = "unbacked_process_mitigation_alteration"
    description = "Manipulated process mitigation policies (CFG/DEP/hard error modes) from dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["defense_evasion", "stealth", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1562"]

    filter_apinames = {
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "NtSetInformationProcess", "SetProcessMitigationPolicy", "SetErrorMode"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.mitigation_events = set()

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "RegionSize") or self.get_argument(call, "dwSize")
            
            if base_address and region_size:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                    
                    if pid not in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = []
                    self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass

        elif api in ("NtSetInformationProcess", "SetProcessMitigationPolicy", "SetErrorMode"):
            caller_addr = call.get("caller")
            
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            info_class = self.get_argument(call, "ProcessInformationClass") or ""
                            proc_name = process.get("process_name", "unknown")
                            
                            # Log the specific class if available (e.g., 93=Mitigation, 12=HardError)
                            class_str = f" (Class: {info_class})" if info_class else ""
                            event_msg = f"{proc_name} executed {api}{class_str} from unbacked caller {caller_addr}"
                            
                            if event_msg not in self.mitigation_events:
                                self.mitigation_events.add(event_msg)
                                self.mark_call()
                                self.ret = True
                            break
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_mitigation_alterations": list(self.mitigation_events)})
        return self.ret
