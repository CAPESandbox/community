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
        "HttpSendRequestA",
        "HttpSendRequestW",
        "InternetConnectA",
        "InternetConnectW",
        "WinHttpSendRequest",
        "WinHttpConnect",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "connect",
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

        if api in ("NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx"):
            base_address = self.get_argument(call, "BaseAddress") or self.get_argument(call, "lpAddress")
            region_size = self.get_argument(call, "RegionSize") or self.get_argument(call, "dwSize")

            if base_address and region_size:
                try:
                    base_val = int(base_address, 16) if isinstance(base_address, str) else int(base_address)
                    size_val = int(region_size, 16) if isinstance(region_size, str) else int(region_size)

                    if pid not in self.unbacked_ranges:
                        self.unbacked_ranges[pid] = []
                    # Append the (start, end) tuple
                    self.unbacked_ranges[pid].append((base_val, base_val + size_val))
                except (ValueError, TypeError):
                    pass

        elif api in (
            "HttpSendRequestA",
            "HttpSendRequestW",
            "InternetConnectA",
            "InternetConnectW",
            "WinHttpSendRequest",
            "WinHttpConnect",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "connect",
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
        ):
            caller_addr = call.get("caller")

            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)

                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        # If the execution pointer that called the Network API is inside our unbacked heap
                        if start_addr <= caller_val <= end_addr:
                            proc_name = process.get("process_name", "unknown")

                            self.unbacked_network_conns.append(
                                f"{proc_name} initiated network API {api} from unbacked caller {caller_addr}"
                            )
                            self.mark_call()
                            self.ret = True
                            break
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

        elif api in ("getaddrinfo", "GetAddrInfoW", "GetAddrInfoExW", "DnsQuery_A", "DnsQuery_W", "DnsQueryEx", "gethostbyname"):
            caller_addr = call.get("caller")

            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)

                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            # FIXED: Added "Name" to catch GetAddrInfoExW correctly
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
                            break
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

    filter_apinames = {"NtAllocateVirtualMemory", "VirtualAlloc", "VirtualAllocEx", "bind", "listen", "accept"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.unbacked_ranges = {}
        self.bind_events = []

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

        elif api in ("bind", "listen", "accept"):
            caller_addr = call.get("caller")

            if caller_addr and pid in self.unbacked_ranges:
                try:
                    caller_val = int(caller_addr, 16) if isinstance(caller_addr, str) else int(caller_addr)

                    for start_addr, end_addr in self.unbacked_ranges[pid]:
                        if start_addr <= caller_val <= end_addr:
                            proc_name = process.get("process_name", "unknown")

                            self.bind_events.append(
                                f"{proc_name} executed {api} (listening for inbound connections) from unbacked caller {caller_addr}"
                            )
                            self.mark_call()
                            self.ret = True
                            break
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

                            self.p2p_pipes.append(
                                f"{proc_name} created P2P Named Pipe '{pipe_name}' from unbacked caller {caller_addr}"
                            )
                            self.mark_call()
                            self.ret = True
                            break
                except (ValueError, TypeError):
                    pass

    def on_complete(self):
        if self.ret:
            self.data.append({"unbacked_p2p_pipes": self.p2p_pipes})
        return self.ret
