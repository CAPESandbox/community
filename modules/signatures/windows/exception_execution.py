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

class ExceptionDrivenExecution(Signature):
    name = "exception_driven_execution"
    description = "Registered a Vectored Exception Handler (VEH) and intentionally triggered exceptions or manipulated thread contexts. May be used to hijack the OS error dispatcher to execute a payload or shellcode"
    severity = 3
    confidence = 50
    categories = ["evasion", "anti_debugging", "stealth", "obfuscation"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055", "T1622"]

    filter_apinames = {
        # VEH Registration
        "RtlAddVectoredExceptionHandler", "AddVectoredExceptionHandler",
        # Context Manipulation (Post-Crash recovery/redirection)
        "NtGetContextThread", "GetThreadContext",
        "NtSetContextThread", "SetThreadContext",
        # Explicit Exception Triggers
        "RaiseException", "RtlRaiseException",
        "DebugBreak", "DbgBreakPoint"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.veh_pids = set()
        self.evasion_events = set()

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id", "unknown")
        proc_name = process.get("process_name", "unknown")

        if api in ("RtlAddVectoredExceptionHandler", "AddVectoredExceptionHandler"):
            self.veh_pids.add(pid)

        elif api in ("RaiseException", "RtlRaiseException", "DebugBreak", "DbgBreakPoint"):
            # If a process registers a VEH and then explicitly raises an exception or debug break, 
            # it is manually passing execution flow to its own handler.
            if pid in self.veh_pids:
                
                trigger_type = "a Software Breakpoint" if "Break" in api else "an explicit Exception"
                event_msg = f"Process '{proc_name}' (PID: {pid}) registered a VEH and then triggered {trigger_type} via {api}. Indicative of Exception-Driven Execution."
                
                if event_msg not in self.evasion_events:
                    self.evasion_events.add(event_msg)
                    self.mark_call()
                    self.ret = True

        elif api in ("NtGetContextThread", "GetThreadContext", "NtSetContextThread", "SetThreadContext"):
            # If the malware used a native CPU fault (like Divide-by-Zero, UD2, or PAGE_NOACCESS), 
            # we won't see the trigger API, but we WILL see it trying to recover the thread context here.
            if pid in self.veh_pids:
                event_msg = f"Process '{proc_name}' (PID: {pid}) registered a VEH and used {api} to inspect/modify CPU registers to redirect execution flow."
                
                if event_msg not in self.evasion_events:
                    self.evasion_events.add(event_msg)
                    self.mark_call()
                    self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"exception_hijacking_events": list(self.evasion_events)})
        return self.ret
      

class AllocatedMemoryProtectionNoAccess(Signature):
    name = "allocated_memory_protection_noaccess"
    description = "Allocated memory and changed its protection to PAGE_NOACCESS, may be used to hide payloads from memory scanners or to trigger an access violation for exception-driven execution"
    severity = 2
    confidence = 100
    categories = ["evasion", "stealth", "defense_evasion", "obfuscation"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1027", "T1055"]

    filter_apinames = {
        # Allocations
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        # Protections
        "NtProtectVirtualMemory", "VirtualProtect", "VirtualProtectEx"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        
        # Track dynamically allocated memory ranges per PID
        self.allocated_memory = {}
        self.locked_payload_events = set()

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id", "unknown")
        proc_name = process.get("process_name", "unknown")

        if pid not in self.allocated_memory:
            self.allocated_memory[pid] = []

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx"):
            base = self.get_argument(call, "BaseAddress") if api == "NtAllocateVirtualMemory" else call.get("retval")
            size = self.get_argument(call, "RegionSize") or self.get_argument(call, "dwSize")
            
            if base and size:
                try:
                    base_val = int(base, 0) if isinstance(base, str) else int(base)
                    size_val = int(size, 0) if isinstance(size, str) else int(size)
                    
                    if base_val:
                        self.allocated_memory[pid].append({
                            "base": base_val,
                            "end": base_val + size_val
                        })
                except (ValueError, TypeError):
                    pass

        elif api in ("NtProtectVirtualMemory", "VirtualProtect", "VirtualProtectEx"):
            protection = self.get_argument(call, "NewAccessProtection") or self.get_argument(call, "flNewProtect")
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            
            if protection and base_address:
                try:
                    prot_val = int(protection, 0) if isinstance(protection, str) else int(protection)
                    base_val = int(base_address, 0) if isinstance(base_address, str) else int(base_address)
                    
                    # 0x01 is the Windows constant for PAGE_NOACCESS
                    if prot_val == 0x01:
                        is_payload = False
                        for mem_range in self.allocated_memory[pid]:
                            if mem_range["base"] <= base_val <= mem_range["end"]:
                                is_payload = True
                                break
                                
                        if is_payload:
                            event_msg = f"Process '{proc_name}' (PID: {pid}) locked dynamically allocated memory at 0x{base_val:x} with PAGE_NOACCESS."
                            if event_msg not in self.locked_payload_events:
                                self.locked_payload_events.add(event_msg)
                                self.mark_call()
                                self.ret = True
                                
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"payload_locking_events": list(self.locked_payload_events)})
        return self.ret
