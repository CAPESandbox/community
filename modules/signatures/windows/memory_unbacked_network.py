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


class UnbackedMemoryNetworkConnection(Signature):
    name = "unbacked_memory_network_connection"
    description = "Network connection initiated from dynamically allocated (unbacked) memory, indicative of fileless C2 activity"
    severity = 3
    confidence = 100
    categories = ["network", "c2", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071", "T1055"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "HttpSendRequestA",
        "HttpSendRequestW",
        "HttpAddRequestHeadersA",
        "HttpAddRequestHeadersW",
        "InternetConnectA",
        "InternetConnectW",
        "WinHttpSendRequest",
        "WinHttpConnect",
        "InternetCrackUrlA",
        "InternetCrackUrlW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "connect",
        "ConnectEx",
        "WSAConnect",
        "send",
        "WSASend",
        "sendto",
        "WSASendTo",
        "recv",
        "WSARecv",
        "recvfrom",
        "WSARecvFrom",
        "InternetReadFile",
        "WinHttpReadData",
        "WinHttpOpenRequest",
        "WinHttpGetProxyForUrl",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.unbacked_network_conns = []

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
                    if t_pid not in self.unbacked_ranges:
                        self.unbacked_ranges[t_pid] = []
                    self.unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [(s, e) for s, e in self.unbacked_ranges[pid] if s != base_val]
                except (ValueError, TypeError):
                    pass
            return

        # filter_apinames only contains alloc/free APIs (handled and returned above)
        # plus network APIs, so anything reaching here is a network call by elimination.
        caller_addr = call.get("caller")
        if caller_addr:
            try:
                caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                    proc_name = process.get("process_name", "unknown")
                    self.unbacked_network_conns.append(
                        f"{proc_name} initiated network API {api} from unbacked caller {caller_addr}"
                    )
                    self.mark_call()
                    self.ret = True
            except (ValueError, TypeError):
                pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_network_connections": self.unbacked_network_conns})
        return self.ret


class UnbackedDnsResolution(Signature):
    name = "unbacked_dns_resolution"
    description = "Attempted to resolve a domain name from dynamically allocated (unbacked) memory"
    severity = 3
    confidence = 100
    categories = ["network", "c2", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071", "T1568"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "getaddrinfo",
        "GetAddrInfoW",
        "GetAddrInfoExW",
        "DnsQuery_A",
        "DnsQuery_W",
        "DnsQueryEx",
        "gethostbyname",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.dns_events = []

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
                    if t_pid not in self.unbacked_ranges:
                        self.unbacked_ranges[t_pid] = []
                    self.unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [(s, e) for s, e in self.unbacked_ranges[pid] if s != base_val]
                except (ValueError, TypeError):
                    pass
            return

        # filter_apinames only contains alloc/free APIs (handled and returned above)
        # plus DNS APIs, so anything reaching here is a DNS call by elimination.
        caller_addr = call.get("caller")
        if caller_addr:
            try:
                caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                    domain = (
                        self.get_argument(call, "Name")
                        or self.get_argument(call, "NodeName")
                        or self.get_argument(call, "pName")
                        or self.get_argument(call, "name")
                        or "Unknown"
                    )
                    proc_name = process.get("process_name", "unknown")
                    self.dns_events.append(f"{proc_name} resolved domain '{domain}' from unbacked caller {caller_addr}")
                    self.mark_call()
                    self.ret = True
            except (ValueError, TypeError):
                pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_dns_resolutions": self.dns_events})
        return self.ret


class UnbackedBindShell(Signature):
    name = "unbacked_bind_shell"
    description = "Bound a network socket to listen for inbound connections from dynamically allocated (unbacked) memory, indicating a fileless TCP bind shell or P2P"
    severity = 3
    confidence = 100
    categories = ["network", "c2", "fileless", "lateral_movement", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1090", "T1570"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "bind",
        "listen",
        "accept",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.bind_events = []

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
                    if t_pid not in self.unbacked_ranges:
                        self.unbacked_ranges[t_pid] = []
                    self.unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [(s, e) for s, e in self.unbacked_ranges[pid] if s != base_val]
                except (ValueError, TypeError):
                    pass
            return

        if api in ("bind", "listen", "accept"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        proc_name = process.get("process_name", "unknown")
                        self.bind_events.append(
                            f"{proc_name} executed {api} (listening for inbound connections) " f"from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_bind_shells": self.bind_events})
        return self.ret


class UnbackedNamedPipeCreation(Signature):
    name = "unbacked_named_pipe_creation"
    description = "Attempted to create a named pipe from dynamically allocated (unbacked) memory, possibly indicative of fileless Peer-to-Peer (P2P) SMB beacon"
    severity = 3
    confidence = 100
    categories = ["command_and_control", "lateral_movement", "fileless"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1090", "T1570"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "CreateNamedPipeW",
        "CreateNamedPipeA",
        "ConnectNamedPipe",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.p2p_pipes = []

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
                    if t_pid not in self.unbacked_ranges:
                        self.unbacked_ranges[t_pid] = []
                    self.unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [(s, e) for s, e in self.unbacked_ranges[pid] if s != base_val]
                except (ValueError, TypeError):
                    pass
            return

        if api in ("CreateNamedPipeW", "CreateNamedPipeA", "ConnectNamedPipe"):
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        pipe_name = self.get_argument(call, "Name") or self.get_argument(call, "lpName") or "Unknown"
                        proc_name = process.get("process_name", "unknown")
                        self.p2p_pipes.append(
                            f"{proc_name} created P2P Named Pipe '{pipe_name}' " f"from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_p2p_pipes": self.p2p_pipes})
        return self.ret


class UnbackedUserAgentRetrieval(Signature):
    name = "unbacked_useragent_retrieval"
    description = "Queried the system's user-agent string from dynamically allocated (unbacked) memory, likely to use in C2 to avoid a hardcoded user-agent"
    severity = 3
    confidence = 100
    categories = ["network", "c2", "defense_evasion", "fileless", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071"]

    filter_apinames = {
        "NtAllocateVirtualMemory",
        "VirtualAlloc",
        "VirtualAllocEx",
        "NtFreeVirtualMemory",
        "VirtualFree",
        "ObtainUserAgentString",
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.ua_events = []

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
                    if t_pid not in self.unbacked_ranges:
                        self.unbacked_ranges[t_pid] = []
                    self.unbacked_ranges[t_pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass
            return

        if api in ("NtFreeVirtualMemory", "VirtualFree"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            if base_address:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    if pid in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = [(s, e) for s, e in self.unbacked_ranges[pid] if s != base_val]
                except (ValueError, TypeError):
                    pass
            return

        if api == "ObtainUserAgentString":
            caller_addr = call.get("caller")
            if caller_addr:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)
                    if any(s <= caller_val <= e for s, e in self.unbacked_ranges.get(pid, [])):
                        ua_string = self.get_argument(call, "UserAgent") or "Unknown UA"
                        proc_name = process.get("process_name", "unknown")
                        ua_display = f"{ua_string[:50]}..." if len(ua_string) > 50 else ua_string
                        self.ua_events.append(
                            f"{proc_name} dynamically retrieved User-Agent '{ua_display}' " f"from unbacked caller {caller_addr}"
                        )
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_useragent_retrieval": self.ua_events})
        return self.ret
