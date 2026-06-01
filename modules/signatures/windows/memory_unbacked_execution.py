# Copyright (C) 2026 Kevin Ross
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

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
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "LdrLoadDll",
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExW",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.suspicious_loads = []

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc"):
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
            return

        if api == "VirtualAllocEx":
            base_address = self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "dwSize")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and region_size and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid != pid:
                        if t_pid not in self.remote_unbacked_ranges:
                            self.remote_unbacked_ranges[t_pid] = []
                        self.remote_unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                    else:
                        if pid not in self.unbacked_ranges:
                            self.unbacked_ranges[pid] = []
                        self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [
                            (s, e) for s, e in self.unbacked_ranges[pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return

        if api == "VirtualFreeEx":
            base_address = self.get_argument(call, "lpAddress")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid in self.remote_unbacked_ranges:
                        self.remote_unbacked_ranges[t_pid] = [
                            (s, e) for s, e in self.remote_unbacked_ranges[t_pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return


        if api in ("LdrLoadDll", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExW"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        dll_name = self.get_argument(call, "FileName") or self.get_argument(call, "lpLibFileName")
                        proc_name = process.get("process_name", "unknown")
                        self.suspicious_loads.append(
                            f"{proc_name} loaded {dll_name} from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_library_loads": self.suspicious_loads})
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
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "AddVectoredExceptionHandler",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.malicious_vehs = []

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc"):
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
            return

        if api == "VirtualAllocEx":
            base_address = self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "dwSize")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and region_size and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid != pid:
                        if t_pid not in self.remote_unbacked_ranges:
                            self.remote_unbacked_ranges[t_pid] = []
                        self.remote_unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                    else:
                        if pid not in self.unbacked_ranges:
                            self.unbacked_ranges[pid] = []
                        self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [
                            (s, e) for s, e in self.unbacked_ranges[pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return

        if api == "VirtualFreeEx":
            base_address = self.get_argument(call, "lpAddress")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid in self.remote_unbacked_ranges:
                        self.remote_unbacked_ranges[t_pid] = [
                            (s, e) for s, e in self.remote_unbacked_ranges[t_pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return


        if api == "AddVectoredExceptionHandler":
            handler_addr = self.get_argument(call, "Handler")
            if handler_addr:
                try:
                    handler_val = int(handler_addr, 16) if isinstance(handler_addr, str) else int(handler_addr)
                    if any(s <= handler_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        proc_name = process.get("process_name", "unknown")
                        self.malicious_vehs.append(
                            f"{proc_name} registered VEH pointing to unbacked memory at {handler_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_veh_handlers": self.malicious_vehs})
        return self.ret


class UnbackedProcessCreation(Signature):
    name = "unbacked_process_creation"
    description = "Attempted to spawn a new child process from dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["execution", "evasion", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055", "T1106"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "CreateProcessInternalW",
        "CreateProcessWithTokenW",
        "NtCreateUserProcess",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.unbacked_processes = []

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc"):
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
            return

        if api == "VirtualAllocEx":
            base_address = self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "dwSize")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and region_size and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid != pid:
                        if t_pid not in self.remote_unbacked_ranges:
                            self.remote_unbacked_ranges[t_pid] = []
                        self.remote_unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                    else:
                        if pid not in self.unbacked_ranges:
                            self.unbacked_ranges[pid] = []
                        self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [
                            (s, e) for s, e in self.unbacked_ranges[pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return

        if api == "VirtualFreeEx":
            base_address = self.get_argument(call, "lpAddress")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid in self.remote_unbacked_ranges:
                        self.remote_unbacked_ranges[t_pid] = [
                            (s, e) for s, e in self.remote_unbacked_ranges[t_pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return


        if api in ("CreateProcessInternalW", "CreateProcessWithTokenW", "NtCreateUserProcess"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        app_name = self.get_argument(call, "ApplicationName") or self.get_argument(call, "CommandLine")
                        proc_name = process.get("process_name", "unknown")
                        self.unbacked_processes.append(
                            f"{proc_name} spawned child process '{app_name}' from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_processes": self.unbacked_processes})
        return self.ret


class UnbackedMemoryApcExecution(Signature):
    name = "unbacked_memory_apc_execution"
    description = "Queues an Asynchronous Procedure Call (APC) where the routine points to dynamically allocated (unbacked) memory, possibly to execute shellcode"
    severity = 3
    confidence = 100
    categories = ["execution", "fileless", "evasion"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtQueueApcThread",
        "QueueUserAPC",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.unbacked_apcs = []

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc"):
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
            return

        if api == "VirtualAllocEx":
            base_address = self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "dwSize")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and region_size and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid != pid:
                        if t_pid not in self.remote_unbacked_ranges:
                            self.remote_unbacked_ranges[t_pid] = []
                        self.remote_unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                    else:
                        if pid not in self.unbacked_ranges:
                            self.unbacked_ranges[pid] = []
                        self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [
                            (s, e) for s, e in self.unbacked_ranges[pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return

        if api == "VirtualFreeEx":
            base_address = self.get_argument(call, "lpAddress")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid in self.remote_unbacked_ranges:
                        self.remote_unbacked_ranges[t_pid] = [
                            (s, e) for s, e in self.remote_unbacked_ranges[t_pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return


        if api in ("NtQueueApcThread", "QueueUserAPC"):
            apc_routine = self.get_argument(call, "ApcRoutine") or self.get_argument(call, "pfnAPC")
            if apc_routine:
                try:
                    apc_val = int(apc_routine, 16) if isinstance(apc_routine, str) else int(apc_routine)

                    # Check both local unbacked memory AND memory previously
                    # allocated into a remote process via VirtualAllocEx.
                    hit_local = any(s <= apc_val <= e for s, e in self.unbacked_ranges.get(pid, []))
                    # For remote APC injection we don't know the target pid from
                    # this call alone; check all remote ranges keyed by any pid.
                    hit_remote = any(
                        any(s <= apc_val <= e for s, e in self.remote_unbacked_ranges.get(tpid, []))
                        for tpid in self.remote_unbacked_ranges
                    )

                    if hit_local or hit_remote:
                        proc_name = process.get("process_name", "unknown")
                        source = "remote unbacked" if hit_remote else "unbacked"
                        self.unbacked_apcs.append(
                            f"Process {proc_name} queued APC to {source} memory at {apc_routine}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_apc_executions": self.unbacked_apcs})
        return self.ret


class ThreadUnbackedMemory(Signature):
    name = "thread_unbacked_memory"
    description = "Creates a thread executing from dynamically allocated (unbacked) memory rather than a file on disk, likely to execute shellcode"
    severity = 3
    confidence = 80
    categories = ["execution", "evasion", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtCreateThreadEx",
        "CreateRemoteThread",
        "CreateThread",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.suspicious_threads = []

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        # Only track executable allocations for this signature
        if api in ("NtAllocateVirtualMemory", "VirtualAlloc"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "RegionSize") or self.get_argument(call, "dwSize")
            protection = self.get_argument(call, "Protection") or self.get_argument(call, "flProtect")
            if base_address and region_size and protection:
                try:
                    prot_val = (
                        int(protection, 16)
                        if isinstance(protection, str) and protection.startswith("0x")
                        else int(protection)
                    )
                    if prot_val in (0x40, 0x20):  # PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_READ
                        base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                        size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                        if pid not in self.unbacked_ranges:
                            self.unbacked_ranges[pid] = []
                        self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api == "VirtualAllocEx":
            base_address = self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "dwSize")
            protection = self.get_argument(call, "flProtect")
            target_pid_raw = self.get_argument(call, "hProcess")
            if base_address and region_size and protection and target_pid_raw:
                try:
                    prot_val = (
                        int(protection, 16)
                        if isinstance(protection, str) and protection.startswith("0x")
                        else int(protection)
                    )
                    if prot_val in (0x40, 0x20):
                        base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                        size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                        t_pid = int(target_pid_raw, 16) if isinstance(target_pid_raw, str) else int(target_pid_raw)
                        if t_pid != pid:
                            if t_pid not in self.remote_unbacked_ranges:
                                self.remote_unbacked_ranges[t_pid] = []
                            self.remote_unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                        else:
                            if pid not in self.unbacked_ranges:
                                self.unbacked_ranges[pid] = []
                            self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        # Free tracking — always remove regardless of original protection flags
        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [
                            (s, e) for s, e in self.unbacked_ranges[pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return

        if api == "VirtualFreeEx":
            base_address = self.get_argument(call, "lpAddress")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid in self.remote_unbacked_ranges:
                        self.remote_unbacked_ranges[t_pid] = [
                            (s, e) for s, e in self.remote_unbacked_ranges[t_pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtCreateThreadEx", "CreateRemoteThread", "CreateThread"):
            start_address = self.get_argument(call, "StartAddress") or self.get_argument(call, "lpStartAddress")
            if start_address:
                try:
                    start_val = int(start_address, 16) if isinstance(start_address, str) else int(start_address)

                    # Local thread into this process's own unbacked memory
                    hit_local = any(s <= start_val <= e for s, e in self.unbacked_ranges.get(pid, []))

                    # Remote thread: start address lands in memory we wrote into another process
                    hit_remote = False
                    if api in ("NtCreateThreadEx", "CreateRemoteThread"):
                        hit_remote = any(
                            any(s <= start_val <= e for s, e in self.remote_unbacked_ranges.get(tpid, []))
                            for tpid in self.remote_unbacked_ranges
                        )

                    if hit_local or hit_remote:
                        proc_name = process.get("process_name", "unknown")
                        source = "remote unbacked" if hit_remote else "unbacked"
                        self.suspicious_threads.append(
                            f"Process {proc_name} (PID {pid}) created thread at {source} address {start_address}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_memory_threads": self.suspicious_threads})
        return self.ret


class UnbackedApiResolution(Signature):
    name = "unbacked_api_resolution"
    description = "Manually resolves API addresses from dynamically allocated (unbacked) memory, indicative of shellcode or an unpacker"
    severity = 3
    confidence = 100
    categories = ["evasion", "shellcode", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1129", "T1055"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "GetProcAddress",
        "LdrGetProcedureAddress",
        "LdrGetProcedureAddressForCaller",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.resolved_apis = set()

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc"):
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
            return

        if api == "VirtualAllocEx":
            base_address = self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "dwSize")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and region_size and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid != pid:
                        if t_pid not in self.remote_unbacked_ranges:
                            self.remote_unbacked_ranges[t_pid] = []
                        self.remote_unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                    else:
                        if pid not in self.unbacked_ranges:
                            self.unbacked_ranges[pid] = []
                        self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [
                            (s, e) for s, e in self.unbacked_ranges[pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return

        if api == "VirtualFreeEx":
            base_address = self.get_argument(call, "lpAddress")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid in self.remote_unbacked_ranges:
                        self.remote_unbacked_ranges[t_pid] = [
                            (s, e) for s, e in self.remote_unbacked_ranges[t_pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return


        if api in ("GetProcAddress", "LdrGetProcedureAddress", "LdrGetProcedureAddressForCaller"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        target_api = (
                            self.get_argument(call, "FunctionName")
                            or self.get_argument(call, "lpProcName")
                            or "Unknown API"
                        )
                        proc_name = process.get("process_name", "unknown")
                        event_msg = f"{proc_name} resolved API '{target_api}' from unbacked caller {caller_addr}"
                        if event_msg not in self.resolved_apis:
                            self.resolved_apis.add(event_msg)
                            self.mark_call()
                            self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_api_resolutions": list(self.resolved_apis)})
        return self.ret


class UnbackedMemoryProtectionAlteration(Signature):
    name = "unbacked_memory_protection_alteration"
    description = "Altered memory protections from dynamically allocated (unbacked) memory, indicative of self-modifying shellcode or memory patching"
    severity = 3
    confidence = 20
    categories = ["evasion", "stealth", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtProtectVirtualMemory",
        "VirtualProtect",
        "VirtualProtectEx",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.protection_events = []

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc"):
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
            return

        if api == "VirtualAllocEx":
            base_address = self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "dwSize")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and region_size and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid != pid:
                        if t_pid not in self.remote_unbacked_ranges:
                            self.remote_unbacked_ranges[t_pid] = []
                        self.remote_unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                    else:
                        if pid not in self.unbacked_ranges:
                            self.unbacked_ranges[pid] = []
                        self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [
                            (s, e) for s, e in self.unbacked_ranges[pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return

        if api == "VirtualFreeEx":
            base_address = self.get_argument(call, "lpAddress")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid in self.remote_unbacked_ranges:
                        self.remote_unbacked_ranges[t_pid] = [
                            (s, e) for s, e in self.remote_unbacked_ranges[t_pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return


        if api in ("NtProtectVirtualMemory", "VirtualProtect", "VirtualProtectEx"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        target_addr = (
                            self.get_argument(call, "BaseAddress")
                            or self.get_argument(call, "lpAddress")
                            or "Unknown"
                        )
                        new_prot = (
                            self.get_argument(call, "NewAccessProtection")
                            or self.get_argument(call, "flNewProtect")
                            or "Unknown"
                        )
                        proc_name = process.get("process_name", "unknown")
                        self.protection_events.append(
                            f"{proc_name} changed memory protection at {target_addr} to {new_prot} "
                            f"from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_memory_protection_alterations": self.protection_events})
        return self.ret


class UnbackedMutexCreation(Signature):
    name = "unbacked_mutex_creation"
    description = "Created or queried a mutex from dynamically allocated (unbacked) memory, indicative of a fileless payload checking or creating an infection marker"
    severity = 3
    confidence = 100
    categories = ["execution", "evasion", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055", "T1480"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtOpenMutant",
        "NtCreateMutant",
        "CreateMutexA",
        "CreateMutexW",
        "CreateMutexExA",
        "CreateMutexExW",
        "OpenMutexA",
        "OpenMutexW",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.mutex_events = set()

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc"):
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
            return

        if api == "VirtualAllocEx":
            base_address = self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "dwSize")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and region_size and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid != pid:
                        if t_pid not in self.remote_unbacked_ranges:
                            self.remote_unbacked_ranges[t_pid] = []
                        self.remote_unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                    else:
                        if pid not in self.unbacked_ranges:
                            self.unbacked_ranges[pid] = []
                        self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [
                            (s, e) for s, e in self.unbacked_ranges[pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return

        if api == "VirtualFreeEx":
            base_address = self.get_argument(call, "lpAddress")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid in self.remote_unbacked_ranges:
                        self.remote_unbacked_ranges[t_pid] = [
                            (s, e) for s, e in self.remote_unbacked_ranges[t_pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return


        if api in (
            "NtOpenMutant", "NtCreateMutant",
            "CreateMutexA", "CreateMutexW", "CreateMutexExA", "CreateMutexExW",
            "OpenMutexA", "OpenMutexW",
        ):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        mutex_name = (
                            self.get_argument(call, "MutexName")
                            or self.get_argument(call, "Name")
                            or self.get_argument(call, "lpName")
                            or "Unknown Mutex"
                        )
                        proc_name = process.get("process_name", "unknown")
                        event_msg = (
                            f"{proc_name} queried/created Mutex '{mutex_name}' "
                            f"from unbacked caller {caller_addr}"
                        )
                        if event_msg not in self.mutex_events:
                            self.mutex_events.add(event_msg)
                            self.mark_call()
                            self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_mutex_creation": list(self.mutex_events)})
        return self.ret


class UnbackedDotNetExecution(Signature):
    name = "unbacked_dotnet_execution"
    description = "Attempted to load .NET DLLs or call CLR APIs from dynamically allocated (unbacked) memory, indicative of fileless .NET"
    severity = 3
    confidence = 100
    categories = ["execution", "fileless", "evasion", "dotnet"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055", "T1564"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "CLRCreateInstance",
        "CorBindToRuntimeEx",
        "CorBindToRuntimeHost",
        "CorBindToCurrentRuntime",
        "LdrLoadDll",
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExW",
    }

    _DOTNET_DLLS = frozenset(["mscoree.dll", "mscoreei.dll", "clr.dll", "coreclr.dll", "mscorwks.dll"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.dotnet_events = set()

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc"):
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
            return

        if api == "VirtualAllocEx":
            base_address = self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "dwSize")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and region_size and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid != pid:
                        if t_pid not in self.remote_unbacked_ranges:
                            self.remote_unbacked_ranges[t_pid] = []
                        self.remote_unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                    else:
                        if pid not in self.unbacked_ranges:
                            self.unbacked_ranges[pid] = []
                        self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [
                            (s, e) for s, e in self.unbacked_ranges[pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return

        if api == "VirtualFreeEx":
            base_address = self.get_argument(call, "lpAddress")
            target_pid = self.get_argument(call, "hProcess")
            if base_address and target_pid:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    t_pid = int(target_pid, 16) if isinstance(target_pid, str) else int(target_pid)
                    if t_pid in self.remote_unbacked_ranges:
                        self.remote_unbacked_ranges[t_pid] = [
                            (s, e) for s, e in self.remote_unbacked_ranges[t_pid] if s != base_val
                        ]
                except (ValueError, TypeError):
                    pass
            return


        caller_addr = call.get("caller")
        if not caller_addr:
            return

        try:
            caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
        except (ValueError, TypeError):
            return

        if not any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
            return

        proc_name = process.get("process_name", "unknown")

        if api in ("CLRCreateInstance", "CorBindToRuntimeEx", "CorBindToRuntimeHost", "CorBindToCurrentRuntime"):
            event_msg = f"{proc_name} bootstrapped .NET CLR via API '{api}' from unbacked caller {caller_addr}"
            if event_msg not in self.dotnet_events:
                self.dotnet_events.add(event_msg)
                self.mark_call()
                self.ret = True

        elif api in ("LdrLoadDll", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExW"):
            dll_name = self.get_argument(call, "FileName") or self.get_argument(call, "lpLibFileName")
            if dll_name and isinstance(dll_name, str):
                if any(t in dll_name.lower() for t in self._DOTNET_DLLS):
                    event_msg = (
                        f"{proc_name} manually loaded .NET engine DLL '{dll_name}' "
                        f"from unbacked caller {caller_addr}"
                    )
                    if event_msg not in self.dotnet_events:
                        self.dotnet_events.add(event_msg)
                        self.mark_call()
                        self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_dotnet_execution": list(self.dotnet_events)})
        return self.ret
