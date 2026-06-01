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

class UnbackedTokenManipulation(Signature):
    name = "unbacked_token_manipulation"
    description = "Attempted to open, duplicate, or impersonate an access token from dynamically allocated (unbacked) memory, indicative of credential theft or lateral movement"
    severity = 3
    confidence = 100
    categories = ["privilege_escalation", "credential_access", "lateral_movement"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1134"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtOpenProcessToken",
        "NtOpenProcessTokenEx",
        "NtDuplicateToken",
        "DuplicateTokenEx",
        "ImpersonateLoggedOnUser",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.token_theft_events = []

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
            "NtOpenProcessToken", "NtOpenProcessTokenEx",
            "NtDuplicateToken", "DuplicateTokenEx",
            "ImpersonateLoggedOnUser",
        ):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        proc_name = process.get("process_name", "unknown")
                        self.token_theft_events.append(
                            f"{proc_name} invoked {api} from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_token_manipulations": self.token_theft_events})
        return self.ret


class UnbackedRegistryModification(Signature):
    name = "unbacked_registry_modification"
    description = "Attempted to modify the Windows registry from dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["persistence", "evasion", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1112", "T1547"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtSetValueKey",
        "RegSetValueExW",
        "RegSetValueExA",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.malicious_registry_writes = []

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


        if api in ("NtSetValueKey", "RegSetValueExW", "RegSetValueExA"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        value_name = (
                            self.get_argument(call, "ValueName")
                            or self.get_argument(call, "lpValueName")
                        )
                        proc_name = process.get("process_name", "unknown")
                        self.malicious_registry_writes.append(
                            f"{proc_name} modified registry value '{value_name}' from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_registry_modifications": self.malicious_registry_writes})
        return self.ret


class UnbackedComInstantiation(Signature):
    name = "unbacked_com_instantiation"
    description = "Attempted to use a COM object (CoCreateInstance) from dynamically allocated (unbacked) memory, possibly for WMI reconnaissance or DCOM lateral movement"
    severity = 3
    confidence = 80
    categories = ["execution", "discovery", "lateral_movement", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1047", "T1559"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "CoCreateInstance",
        "CoCreateInstanceEx",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.com_events = []

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


        if api in ("CoCreateInstance", "CoCreateInstanceEx"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        clsid = self.get_argument(call, "rclsid") or "Unknown CLSID"
                        proc_name = process.get("process_name", "unknown")
                        self.com_events.append(
                            f"{proc_name} instantiated COM object {clsid} from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_com_instantiations": self.com_events})
        return self.ret


class UnbackedCryptoOperations(Signature):
    name = "unbacked_crypto_operations"
    description = "Invoked native Windows cryptographic APIs from dynamically allocated (unbacked) memory, possible encryption/decryption of payloads, c2, files or data"
    severity = 3
    confidence = 40
    categories = ["evasion", "c2", "fileless", "obfuscation", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1027", "T1573"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "CryptEncrypt",
        "CryptDecrypt",
        "BCryptEncrypt",
        "BCryptDecrypt",
        "CryptHashData",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.crypto_events = []

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


        if api in ("CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt", "CryptHashData"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        proc_name = process.get("process_name", "unknown")
                        self.crypto_events.append(
                            f"{proc_name} executed {api} from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_crypto_operations": self.crypto_events})
        return self.ret


class UnbackedServiceManipulation(Signature):
    name = "unbacked_service_manipulation"
    description = "Attempted to interact with the Service Control Manager from dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["lateral_movement", "persistence", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1543", "T1569"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "OpenSCManagerA",
        "OpenSCManagerW",
        "CreateServiceA",
        "CreateServiceW",
        "StartServiceA",
        "StartServiceW",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.scm_events = []

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
            "OpenSCManagerA", "OpenSCManagerW",
            "CreateServiceA", "CreateServiceW",
            "StartServiceA", "StartServiceW",
        ):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        machine_name = (
                            self.get_argument(call, "MachineName")
                            or self.get_argument(call, "lpMachineName")
                            or "Localhost"
                        )
                        service_name = (
                            self.get_argument(call, "ServiceName")
                            or self.get_argument(call, "lpServiceName")
                            or "Unknown"
                        )
                        proc_name = process.get("process_name", "unknown")
                        self.scm_events.append(
                            f"{proc_name} executed {api} targeting {machine_name}\\{service_name} "
                            f"from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_service_manipulations": self.scm_events})
        return self.ret


class UnbackedFileDropping(Signature):
    name = "unbacked_file_dropping"
    description = "Wrote data to the filesystem from dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["execution", "exfiltration", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1105", "T1074"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtWriteFile",
        "WriteFile",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.file_drops = []

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


        if api in ("NtWriteFile", "WriteFile"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        file_name = (
                            self.get_argument(call, "FileName")
                            or self.get_argument(call, "HandleName")
                            or "Unknown Handle"
                        )
                        proc_name = process.get("process_name", "unknown")
                        self.file_drops.append(
                            f"{proc_name} wrote to file '{file_name}' from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_file_drops": self.file_drops})
        return self.ret


class UnbackedDelayExecution(Signature):
    name = "unbacked_delay_execution"
    description = "Paused execution (sleep/delay) in a thread executing in dynamically allocated (unbacked) memory, indicative of sandbox evasion or C2 sleeping between callbacks"
    severity = 3
    confidence = 100
    categories = ["evasion", "c2", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1027", "T1497"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtDelayExecution",
        "Sleep",
        "SleepEx",
        "WaitForSingleObject",
        "WaitForSingleObjectEx",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.delay_events = set()

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


        if api in ("NtDelayExecution", "Sleep", "SleepEx", "WaitForSingleObject", "WaitForSingleObjectEx"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        proc_name = process.get("process_name", "unknown")
                        delay_time = (
                            self.get_argument(call, "Milliseconds")
                            or self.get_argument(call, "DelayInterval")
                            or "Unknown Time"
                        )
                        event_msg = (
                            f"{proc_name} executed {api} (Time: {delay_time}) "
                            f"from unbacked caller {caller_addr}"
                        )
                        if event_msg not in self.delay_events:
                            self.delay_events.add(event_msg)
                            self.mark_call()
                            self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_delay_executions": list(self.delay_events)})
        return self.ret


class UnbackedWmiExecution(Signature):
    name = "unbacked_wmi_execution"
    description = "Invoked a WMI method from a thread executing in dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["execution", "lateral_movement", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1047"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "IWbemServices_ExecMethod",
        "IWbemServices_ExecMethodAsync",
        "WMIExec",
        "WMIExecute",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.wmi_executions = []

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


        if api in ("IWbemServices_ExecMethod", "IWbemServices_ExecMethodAsync", "WMIExec", "WMIExecute"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        obj_path = (
                            self.get_argument(call, "ObjectPath")
                            or self.get_argument(call, "strObjectPath")
                            or "Unknown Object"
                        )
                        method_name = (
                            self.get_argument(call, "MethodName")
                            or self.get_argument(call, "strMethodName")
                            or "Unknown Method"
                        )
                        proc_name = process.get("process_name", "unknown")
                        self.wmi_executions.append(
                            f"{proc_name} executed WMI Method '{obj_path}::{method_name}' "
                            f"from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_wmi_executions": self.wmi_executions})
        return self.ret


class UnbackedProcessEnumeration(Signature):
    name = "unbacked_process_enumeration"
    description = "Attempted to enumerate running processes from dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["discovery", "fileless", "reconnaissance", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1057"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "CreateToolhelp32Snapshot",
        "EnumProcesses",
        "NtQuerySystemInformation",
        "Process32FirstW",
        "Process32NextW",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.enum_events = []

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
            "CreateToolhelp32Snapshot", "EnumProcesses",
            "NtQuerySystemInformation",
            "Process32FirstW", "Process32NextW",
        ):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        # For NtQuerySystemInformation only fire on class 5 (SystemProcessInformation)
                        if api == "NtQuerySystemInformation":
                            info_class = self.get_argument(call, "SystemInformationClass")
                            if str(info_class) != "5":
                                return
                        proc_name = process.get("process_name", "unknown")
                        event_msg = (
                            f"{proc_name} executed {api} (Process Discovery) "
                            f"from unbacked caller {caller_addr}"
                        )
                        if event_msg not in self.enum_events:
                            self.enum_events.append(event_msg)
                            self.mark_call()
                            self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_process_enumerations": self.enum_events})
        return self.ret
        

class UnbackedScheduledTaskCreation(Signature):
    name = "unbacked_scheduled_task_creation"
    description = "Created or registered a scheduled task from dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["persistence", "fileless", "execution"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1053.005"]

    # Well-known Task Scheduler CLSIDs surfaced by CoCreateInstance.
    # {0F87369F-...} = ITaskScheduler service
    # {148BD52A-...} = Task (v1 legacy)
    # {148BD520-...} = TaskScheduler (v1 legacy)
    TASK_SCHEDULER_CLSIDS = {
        "{0f87369f-a4e5-11d1-9781-00c04fd91ac0}",
        "{148bd52a-a2ab-11ce-b11f-00aa00530503}",
        "{148bd520-a2ab-11ce-b11f-00aa00530503}",
    }

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "CoCreateInstance",
        "CoCreateInstanceEx",
        "SchRpcRegisterTask",
        "ITaskScheduler_NewWorkItem",
        "ITaskScheduler_AddWorkItem",
        "IRegisteredTaskCollection_get_Item",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.task_events = set()

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

        in_unbacked = any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, []))
        if not in_unbacked:
            return

        proc_name = process.get("process_name", "unknown")

        if api in ("CoCreateInstance", "CoCreateInstanceEx"):
            clsid = (self.get_argument(call, "rclsid") or "").lower()
            if clsid not in self.TASK_SCHEDULER_CLSIDS:
                return
            event_msg = (
                f"{proc_name} instantiated Task Scheduler COM object ({clsid}) "
                f"from unbacked caller {caller_addr}"
            )

        elif api == "SchRpcRegisterTask":
            task_path = self.get_argument(call, "path") or "Unknown Path"
            event_msg = (
                f"{proc_name} registered scheduled task '{task_path}' via SchRpcRegisterTask "
                f"from unbacked caller {caller_addr}"
            )

        elif api in ("ITaskScheduler_NewWorkItem", "ITaskScheduler_AddWorkItem", "IRegisteredTaskCollection_get_Item"):
            task_name = (
                self.get_argument(call, "pwszTaskName")
                or self.get_argument(call, "pwszTaskFolderName")
                or "Unknown Task"
            )
            event_msg = (
                f"{proc_name} called {api} (task: '{task_name}') "
                f"from unbacked caller {caller_addr}"
            )

        else:
            return

        if event_msg not in self.task_events:
            self.task_events.add(event_msg)
            self.mark_call()
            self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_scheduled_task_creations": list(self.task_events)})
        return self.ret


class UnbackedPrivilegeEscalation(Signature):
    name = "unbacked_privilege_escalation"
    description = (
        "Enabled sensitive privileges (e.g. SeDebugPrivilege, SeTcbPrivilege) via token adjustment "
        "from dynamically allocated (unbacked) memory, indicative of shellcode preparing for "
        "privileged operations"
    )
    severity = 3
    confidence = 100
    categories = ["privilege_escalation", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1134.001"]

    HIGH_VALUE_PRIVILEGES = {
        "sedebugprivilege",
        "setcbprivilege",
        "seassignprimarytokenprivilege",
        "seimpersonateprivilege",
        "seloaddriverprivilege",
        "serestoreprivilege",
        "setakeownershipprivilege",
        "sesecurityprivilege",
        "sebackupprivilege",
        "secreatepermanentprivilege",
    }

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtAdjustPrivilegesToken",
        "AdjustTokenPrivileges",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.priv_events = set()

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

        if api not in ("NtAdjustPrivilegesToken", "AdjustTokenPrivileges"):
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

        priv_name = (
            self.get_argument(call, "PrivilegeName")
            or self.get_argument(call, "Privileges")
            or self.get_argument(call, "NewState")
            or "Unknown Privilege"
        )
        priv_lower = priv_name.lower() if isinstance(priv_name, str) else ""
        is_high_value = (
            any(p in priv_lower for p in self.HIGH_VALUE_PRIVILEGES)
            or priv_lower == "unknown privilege"
        )
        if not is_high_value:
            return

        proc_name = process.get("process_name", "unknown")
        event_msg = (
            f"{proc_name} adjusted token privileges ({priv_name}) via {api} "
            f"from unbacked caller {caller_addr}"
        )
        if event_msg not in self.priv_events:
            self.priv_events.add(event_msg)
            self.mark_call()
            self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_privilege_escalations": list(self.priv_events)})
        return self.ret


class UnbackedNtdllUnhooking(Signature):
    name = "unbacked_ntdll_unhooking"
    description = (
        "Read a clean copy of ntdll.dll or kernel32.dll from disk then altered memory protections "
        "and wrote into the loaded module from dynamically allocated (unbacked) memory — the "
        "canonical EDR unhooking technique"
    )
    severity = 3
    confidence = 100
    categories = ["defense_evasion", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1562.001"]

    TARGET_MODULES = (
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "wow64.dll",
        "wow64win.dll",
    )

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtReadFile",
        "ReadFile",
        "NtProtectVirtualMemory",
        "VirtualProtect",
        "VirtualProtectEx",
        "NtWriteVirtualMemory",
        "WriteProcessMemory",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self._pid_phases = {}
        self.unhook_events = set()

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

        if api in ("NtReadFile", "ReadFile"):
            file_path = (
                self.get_argument(call, "HandleName")
                or self.get_argument(call, "FileName")
                or ""
            ).lower()
            if any(mod in file_path for mod in self.TARGET_MODULES):
                if pid not in self._pid_phases:
                    self._pid_phases[pid] = set()
                self._pid_phases[pid].add("read")
                event_msg = (
                    f"{proc_name} read module from disk ('{file_path}') "
                    f"from unbacked caller {caller_addr}"
                )
                if event_msg not in self.unhook_events:
                    self.unhook_events.add(event_msg)
                    self.mark_call()

        elif api in ("NtProtectVirtualMemory", "VirtualProtect", "VirtualProtectEx"):
            new_prot = (
                self.get_argument(call, "NewAccessProtection")
                or self.get_argument(call, "flNewProtect")
                or ""
            )
            try:
                prot_val = (
                    int(new_prot, 16)
                    if isinstance(new_prot, str) and new_prot.startswith("0x")
                    else int(new_prot)
                )
                # PAGE_READWRITE (0x04), PAGE_WRITECOPY (0x08),
                # PAGE_EXECUTE_READWRITE (0x40), PAGE_EXECUTE_WRITECOPY (0x80)
                if prot_val in (0x04, 0x08, 0x40, 0x80):
                    if pid not in self._pid_phases:
                        self._pid_phases[pid] = set()
                    self._pid_phases[pid].add("protect")
                    event_msg = (
                        f"{proc_name} changed module memory protection to 0x{prot_val:02X} "
                        f"from unbacked caller {caller_addr}"
                    )
                    if event_msg not in self.unhook_events:
                        self.unhook_events.add(event_msg)
                        self.mark_call()
            except (ValueError, TypeError):
                pass

        elif api in ("NtWriteVirtualMemory", "WriteProcessMemory"):
            phases = self._pid_phases.get(pid, set())
            if "read" in phases and "protect" in phases:
                target_addr = (
                    self.get_argument(call, "BaseAddress")
                    or self.get_argument(call, "lpBaseAddress")
                    or "Unknown"
                )
                event_msg = (
                    f"{proc_name} overwrote loaded module memory at {target_addr} "
                    f"from unbacked caller {caller_addr} (EDR unhooking sequence complete)"
                )
                if event_msg not in self.unhook_events:
                    self.unhook_events.add(event_msg)
                    self.mark_call()
                    self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_ntdll_unhooking": list(self.unhook_events)})
        return self.ret


class UnbackedHardwareBreakpointSet(Signature):
    name = "unbacked_hardware_breakpoint_set"
    description = (
        "Set hardware debug registers (Dr0-Dr3) via NtSetContextThread from dynamically allocated "
        "(unbacked) memory, indicative of HWBP-based syscall hooking used by evasive C2 frameworks "
        "(Sliver, SilentMoonwalk)"
    )
    severity = 3
    confidence = 100
    categories = ["defense_evasion", "anti_debugging", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1622", "T1562.001"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtSetContextThread",
        "SetThreadContext",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.hwbp_events = set()

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

        if api not in ("NtSetContextThread", "SetThreadContext"):
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

        def _parse_reg(name):
            v = self.get_argument(call, name) or "0"
            try:
                return int(v, 16) if isinstance(v, str) else int(v)
            except (ValueError, TypeError):
                return 0

        set_regs = {}
        for reg in ("Dr0", "Dr1", "Dr2", "Dr3"):
            val = _parse_reg(reg)
            if val != 0:
                set_regs[reg] = hex(val)

        if not set_regs:
            return

        proc_name = process.get("process_name", "unknown")
        regs_str = ", ".join(f"{k}={v}" for k, v in set_regs.items())
        event_msg = (
            f"{proc_name} set hardware breakpoint registers ({regs_str}) via {api} "
            f"from unbacked caller {caller_addr}"
        )
        if event_msg not in self.hwbp_events:
            self.hwbp_events.add(event_msg)
            self.mark_call()
            self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_hardware_breakpoints": list(self.hwbp_events)})
        return self.ret


class UnbackedEtwPatching(Signature):
    name = "unbacked_etw_patching"
    description = (
        "Attempted to blind ETW telemetry by writing into ntdll!EtwEventWrite from dynamically "
        "allocated (unbacked) memory — a technique used by Brute Ratel, Havoc C2, and similar "
        "offensive frameworks to suppress event-tracing visibility"
    )
    severity = 3
    confidence = 100
    categories = ["defense_evasion", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1562.006"]

    ETW_TARGETS = (
        "etweventwrite",
        "etw_write",
        "ntdll",
    )

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
        "NtWriteVirtualMemory",
        "WriteProcessMemory",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self._pid_phases = {}
        self.etw_events = set()

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

        if api in ("NtProtectVirtualMemory", "VirtualProtect", "VirtualProtectEx"):
            target_addr = (
                self.get_argument(call, "BaseAddress")
                or self.get_argument(call, "lpAddress")
                or ""
            ).lower()
            module_label = (self.get_argument(call, "ModuleName") or "").lower()
            if "ntdll" in target_addr + " " + module_label:
                if pid not in self._pid_phases:
                    self._pid_phases[pid] = set()
                self._pid_phases[pid].add("protect")

        elif api in ("NtWriteVirtualMemory", "WriteProcessMemory"):
            target_label = (
                self.get_argument(call, "BaseAddress")
                or self.get_argument(call, "lpBaseAddress")
                or self.get_argument(call, "ModuleName")
                or self.get_argument(call, "HandleName")
                or ""
            ).lower()
            is_etw_target = any(t in target_label for t in self.ETW_TARGETS)
            has_prior_protect = "protect" in self._pid_phases.get(pid, set())
            if is_etw_target or has_prior_protect:
                event_msg = (
                    f"{proc_name} wrote into ETW/ntdll region (target: '{target_label or 'unknown'}') "
                    f"from unbacked caller {caller_addr}"
                )
                if event_msg not in self.etw_events:
                    self.etw_events.add(event_msg)
                    self.mark_call()
                    self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_etw_patching": list(self.etw_events)})
        return self.ret


class UnbackedAmsiPatching(Signature):
    name = "unbacked_amsi_patching"
    description = (
        "Attempted to patch AMSI (Anti-Malware Scan Interface) by writing into amsi.dll or "
        "AmsiScanBuffer from dynamically allocated (unbacked) memory"
    )
    severity = 3
    confidence = 100
    categories = ["defense_evasion", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1562.001"]

    AMSI_TARGETS = (
        "amsiscanbuffer",
        "amsiutils",
        "amsi.dll",
        "amsi",
    )

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
        "NtWriteVirtualMemory",
        "WriteProcessMemory",
        "LdrUnloadDll",
        "FreeLibrary",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self._pid_phases = {}
        self.amsi_events = set()

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

        if api in ("NtProtectVirtualMemory", "VirtualProtect", "VirtualProtectEx"):
            target_addr = (
                self.get_argument(call, "BaseAddress")
                or self.get_argument(call, "lpAddress")
                or ""
            ).lower()
            module_label = (self.get_argument(call, "ModuleName") or "").lower()
            if any(t in target_addr + " " + module_label for t in self.AMSI_TARGETS):
                if pid not in self._pid_phases:
                    self._pid_phases[pid] = set()
                self._pid_phases[pid].add("protect")

        elif api in ("NtWriteVirtualMemory", "WriteProcessMemory"):
            target_label = (
                self.get_argument(call, "BaseAddress")
                or self.get_argument(call, "lpBaseAddress")
                or self.get_argument(call, "ModuleName")
                or self.get_argument(call, "HandleName")
                or ""
            ).lower()
            is_amsi_target = any(t in target_label for t in self.AMSI_TARGETS)
            has_prior_protect = "protect" in self._pid_phases.get(pid, set())
            if is_amsi_target or has_prior_protect:
                event_msg = (
                    f"{proc_name} wrote into AMSI region (target: '{target_label or 'unknown'}') "
                    f"from unbacked caller {caller_addr}"
                )
                if event_msg not in self.amsi_events:
                    self.amsi_events.add(event_msg)
                    self.mark_call()
                    self.ret = True

        elif api in ("LdrUnloadDll", "FreeLibrary"):
            dll_name = (
                self.get_argument(call, "FileName")
                or self.get_argument(call, "lpLibFileName")
                or ""
            ).lower()
            if any(t in dll_name for t in self.AMSI_TARGETS):
                event_msg = (
                    f"{proc_name} unloaded AMSI DLL ('{dll_name}') "
                    f"from unbacked caller {caller_addr}"
                )
                if event_msg not in self.amsi_events:
                    self.amsi_events.add(event_msg)
                    self.mark_call()
                    self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_amsi_patching": list(self.amsi_events)})
        return self.ret


class UnbackedDebugObjectQuery(Signature):
    name = "unbacked_debug_object_query"
    description = (
        "Queried process debug port or debug object handle via NtQueryInformationProcess from "
        "dynamically allocated (unbacked) memory, indicative of shellcode performing debugger "
        "detection"
    )
    severity = 3
    confidence = 100
    categories = ["defense_evasion", "anti_debugging", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1622"]

    # 7  = ProcessDebugPort
    # 30 = ProcessDebugObjectHandle
    # 31 = ProcessDebugFlags
    # 34 = ProcessBreakOnTermination
    DEBUGGER_INFO_CLASSES = {"7", "30", "31", "34"}

    CLASS_LABELS = {
        "7":  "ProcessDebugPort",
        "30": "ProcessDebugObjectHandle",
        "31": "ProcessDebugFlags",
        "34": "ProcessBreakOnTermination",
    }

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "VirtualFreeEx",
        "NtQueryInformationProcess",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.remote_unbacked_ranges = {}
        self.debug_events = set()

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

        if api != "NtQueryInformationProcess":
            return

        info_class = str(self.get_argument(call, "ProcessInformationClass") or "")
        if info_class not in self.DEBUGGER_INFO_CLASSES:
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

        class_label = self.CLASS_LABELS.get(info_class, f"class {info_class}")
        proc_name = process.get("process_name", "unknown")
        event_msg = (
            f"{proc_name} queried {class_label} (class {info_class}) "
            f"from unbacked caller {caller_addr}"
        )
        if event_msg not in self.debug_events:
            self.debug_events.add(event_msg)
            self.mark_call()
            self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_debug_object_queries": list(self.debug_events)})
        return self.ret
