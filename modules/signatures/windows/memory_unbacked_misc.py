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


class UnbackedTokenManipulation(Signature):
    name = "unbacked_token_manipulation"
    description = "Attempted to open, duplicate, or impersonate an access token from dynamically allocated (unbacked) memory, indicative credential theft or lateral movement"
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


class UnbackedRegistryModication(Signature):
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
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "CoCreateInstance", "CoCreateInstanceEx"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.com_events = []

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

        elif api in ("CoCreateInstance", "CoCreateInstanceEx"):
            caller_addr = call.get("caller")
            
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            clsid = self.get_argument(call, "rclsid") or "Unknown CLSID"
                            proc_name = process.get("process_name", "unknown")
                            
                            self.com_events.append(f"{proc_name} instantiated COM object {clsid} from unbacked caller {caller_addr}")
                            self.mark_call()
                            self.ret = True
                            break
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
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt", "CryptHashData"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.crypto_events = []

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

        elif api in ("CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt", "CryptHashData"):
            caller_addr = call.get("caller")
            
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            proc_name = process.get("process_name", "unknown")
                            
                            self.crypto_events.append(f"{proc_name} executed {api} from unbacked caller {caller_addr}")
                            self.mark_call()
                            self.ret = True
                            break
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
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.scm_events = []

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

        elif api in ("OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"):
            caller_addr = call.get("caller")
            
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            machine_name = self.get_argument(call, "MachineName") or self.get_argument(call, "lpMachineName") or "Localhost"
                            service_name = self.get_argument(call, "ServiceName") or self.get_argument(call, "lpServiceName") or "Unknown"
                            proc_name = process.get("process_name", "unknown")
                            
                            self.scm_events.append(f"{proc_name} executed {api} targeting {machine_name}\\{service_name} from unbacked caller {caller_addr}")
                            self.mark_call()
                            self.ret = True
                            break
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_service_manipulations": self.scm_events})
        return self.ret
        

class UnbackedFileDropping(Signature):
    name = "unbacked_file_dropping"
    description = "Attempted to write data to the filesystem from dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["execution", "exfiltration", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1105", "T1074"]

    filter_apinames = {
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "NtWriteFile", "WriteFile"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.file_drops = []

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

        elif api in ("NtWriteFile", "WriteFile"):
            caller_addr = call.get("caller")
            
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            file_name = self.get_argument(call, "FileName") or self.get_argument(call, "HandleName") or "Unknown Handle"
                            proc_name = process.get("process_name", "unknown")
                            
                            self.file_drops.append(f"{proc_name} wrote to file '{file_name}' from unbacked caller {caller_addr}")
                            self.mark_call()
                            self.ret = True
                            break
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
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "NtDelayExecution", "Sleep", "SleepEx", "WaitForSingleObject", "WaitForSingleObjectEx"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.delay_events = set()

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

        elif api in ("NtDelayExecution", "Sleep", "SleepEx", "WaitForSingleObject", "WaitForSingleObjectEx"):
            caller_addr = call.get("caller")           
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)                 
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            proc_name = process.get("process_name", "unknown")
                            delay_time = self.get_argument(call, "Milliseconds") or self.get_argument(call, "DelayInterval") or "Unknown Time"                    
                            event_msg = f"{proc_name} executed {api} (Time: {delay_time}) from unbacked caller {caller_addr}"
                            if event_msg not in self.delay_events:
                                self.delay_events.add(event_msg)
                                self.mark_call()
                                self.ret = True
                            break
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
        "NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx",
        "IWbemServices_ExecMethod", "IWbemServices_ExecMethodAsync", 
        "WMIExec", "WMIExecute"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.wmi_executions = []

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

        elif api in ("IWbemServices_ExecMethod", "IWbemServices_ExecMethodAsync", "WMIExec", "WMIExecute"):
            caller_addr = call.get("caller")
            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    
                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            obj_path = self.get_argument(call, "ObjectPath") or self.get_argument(call, "strObjectPath") or "Unknown Object"
                            method_name = self.get_argument(call, "MethodName") or self.get_argument(call, "strMethodName") or "Unknown Method"
                            proc_name = process.get("process_name", "unknown")
                            self.wmi_executions.append(f"{proc_name} executed WMI Method '{obj_path}::{method_name}' from unbacked caller {caller_addr}")
                            self.mark_call()
                            self.ret = True
                            break
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_wmi_executions": self.wmi_executions})
        return self.ret
