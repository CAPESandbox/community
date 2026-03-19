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

class UnbackedLibraryLoad(Signature):
    name = "unbacked_library_load"
    description = "Loads a new DLL where the caller address originates from dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["evasion", "execution", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1129", "T1059"]

    filter_apinames = {
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "LdrLoadDll", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExW"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {} # { pid: [(start_addr, end_addr)] }
        self.suspicious_loads = []

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        # 1. Track the exact boundaries of unbacked memory allocations
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

        # 2. Check if a DLL is loaded BY that unbacked memory
        elif api in ("LdrLoadDll", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExW"):
            caller_addr = call.get("caller")
            
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            dll_name = self.get_argument(call, "FileName") or self.get_argument(call, "lpLibFileName")
                            proc_name = process.get("process_name", "unknown")
                            
                            self.suspicious_loads.append(f"{proc_name} loaded {dll_name} from unbacked caller {caller_addr}")
                            self.mark_call()
                            self.ret = True
                            break
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_library_loads": self.suspicious_loads})
        return self.ret


class UnbackedTokenManipulation(Signature):
    name = "unbacked_token_manipulation"
    description = "A thread executing in unbacked memory attempted to open, duplicate, or impersonate an access token, indicative credential theft or lateral movement"
    severity = 3
    confidence = 100
    categories = ["privilege_escalation", "credential_access", "lateral_movement"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1134"]

    filter_apinames = {
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "NtOpenProcessToken", "NtOpenProcessTokenEx", "NtDuplicateToken", "DuplicateTokenEx", "ImpersonateLoggedOnUser"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.token_theft_events = []

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

        elif api in ("NtOpenProcessToken", "NtOpenProcessTokenEx", "NtDuplicateToken", "DuplicateTokenEx", "ImpersonateLoggedOnUser"):
            caller_addr = call.get("caller")
            
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            proc_name = process.get("process_name", "unknown")
                            
                            self.token_theft_events.append(f"{proc_name} invoked {api} from unbacked caller {caller_addr}")
                            self.mark_call()
                            self.ret = True
                            break
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_token_manipulations": self.token_theft_events})
        return self.ret


class UnbackedRegistryPersistence(Signature):
    name = "unbacked_registry_persistence"
    description = "A thread executing in unbacked memory attempted to modify the Windows registry"
    severity = 3
    confidence = 100
    categories = ["persistence", "evasion", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1112", "T1547"]

    filter_apinames = {
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "NtSetValueKey", "RegSetValueExW", "RegSetValueExA"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.malicious_registry_writes = []

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

        elif api in ("NtSetValueKey", "RegSetValueExW", "RegSetValueExA"):
            caller_addr = call.get("caller")
            
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            value_name = self.get_argument(call, "ValueName") or self.get_argument(call, "lpValueName")
                            proc_name = process.get("process_name", "unknown")
                            
                            self.malicious_registry_writes.append(f"{proc_name} modified registry value '{value_name}' from unbacked caller {caller_addr}")
                            self.mark_call()
                            self.ret = True
                            break
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_registry_modifications": self.malicious_registry_writes})
        return self.ret


class UnbackedMemoryNetworkConnection(Signature):
    name = "unbacked_memory_network_connection"
    description = "Network connection from a thread executing in dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["network", "c2", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071", "T1055"] 

    filter_apinames = {
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "NtCreateThreadEx", "CreateThread",
        "HttpSendRequestA", "HttpSendRequestW", "InternetConnectA", "connect", "send"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_allocations = {}
        self.malicious_threads = set() 
        self.unbacked_network_conns = []

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")
        tid = call.get("thread_id")

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx"):
            address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if address:
                if pid not in self.unbacked_allocations:
                    self.unbacked_allocations[pid] = set()
                self.unbacked_allocations[pid].add(str(address).lower())

        elif api in ("NtCreateThreadEx", "CreateThread"):
            if pid in self.unbacked_allocations:
                start_address = self.get_argument(call, "StartAddress") or self.get_argument(call, "lpStartAddress")
                
                if start_address and str(start_address).lower() in self.unbacked_allocations[pid]:
                    new_tid = self.get_argument(call, "ThreadId") or self.get_argument(call, "lpThreadId")
                    if new_tid:
                        self.malicious_threads.add(str(new_tid))

        elif api in ("HttpSendRequestA", "HttpSendRequestW", "InternetConnectA", "connect", "send"):
            if tid and str(tid) in self.malicious_threads:
                proc_name = process.get("process_name", "unknown")
                self.unbacked_network_conns.append(f"Thread {tid} in {proc_name} initiated network API {api} from unbacked memory")
                self.mark_call()
                self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_network_connections": self.unbacked_network_conns})
        return self.ret


class UnbackedNamedPipeCreation(Signature):
    name = "unbacked_named_pipe_creation"
    description = "A thread executing in unbacked memory attempting to create a named pipe, possibly indicative of a Peer-to-Peer (P2P) SMB beacon initializing"
    severity = 3
    confidence = 100
    categories = ["command_and_control", "lateral_movement", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1090", "T1570"]

    filter_apinames = {
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "CreateNamedPipeW", "CreateNamedPipeA", "ConnectNamedPipe"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.p2p_pipes = []

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

        elif api in ("CreateNamedPipeW", "CreateNamedPipeA", "ConnectNamedPipe"):
            caller_addr = call.get("caller")
            
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            pipe_name = self.get_argument(call, "Name") or self.get_argument(call, "lpName") or "Unknown"
                            proc_name = process.get("process_name", "unknown")
                            
                            self.p2p_pipes.append(f"{proc_name} created P2P Named Pipe '{pipe_name}' from unbacked caller {caller_addr}")
                            self.mark_call()
                            self.ret = True
                            break
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_p2p_pipes": self.p2p_pipes})
        return self.ret


class UnbackedVehRegistration(Signature):
    name = "unbacked_veh_registration"
    description = "Registers a Vectored Exception Handler (VEH) where the callback function points to unbacked memory, indicating hardware breakpoint hooking or obfuscation"
    severity = 3
    confidence = 100
    categories = ["evasion", "defense_evasion", "stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1562", "T1055"]

    filter_apinames = {
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "AddVectoredExceptionHandler"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.malicious_vehs = []

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

        elif api == "AddVectoredExceptionHandler":
            handler_addr = self.get_argument(call, "Handler")
            
            if handler_addr and pid in self.unbacked_ranges:
                try:
                    handler_val = int(handler_addr, 16) if isinstance(handler_addr, str) else int(handler_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        # If the registered handler points inside our unbacked ranges
                        if start_addr <= handler_val <= end_addr:
                            proc_name = process.get("process_name", "unknown")
                            
                            self.malicious_vehs.append(f"{proc_name} registered VEH pointing to unbacked memory at {handler_addr}")
                            self.mark_call()
                            self.ret = True
                            break
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_veh_handlers": self.malicious_vehs})
        return self.ret


class UnbackedProcessCreation(Signature):
    name = "unbacked_process_creation"
    description = "Thread executing in unbacked memory attempted to spawn a new child process"
    severity = 3
    confidence = 100
    categories = ["execution", "evasion", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055", "T1106"]

    filter_apinames = {
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "CreateProcessInternalW", "CreateProcessWithTokenW", "NtCreateUserProcess"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.unbacked_processes = []

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

        elif api in ("CreateProcessInternalW", "CreateProcessWithTokenW", "NtCreateUserProcess"):
            caller_addr = call.get("caller")
            
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            app_name = self.get_argument(call, "ApplicationName") or self.get_argument(call, "CommandLine")
                            proc_name = process.get("process_name", "unknown")
                            
                            self.unbacked_processes.append(f"{proc_name} spawned sacrificial child '{app_name}' from unbacked caller {caller_addr}")
                            self.mark_call()
                            self.ret = True
                            break
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_processes": self.unbacked_processes})
        return self.ret
