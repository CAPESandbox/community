# Copyright (C) 2026 Kevin Ross & Gemini
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

class InterProcessCommsNamedPipe(Signature):
    name = "interprocess_comms_named_pipe"
    description = "Inter-process communication via named pipes, possibly to route local C2 traffic"
    severity = 3
    confidence = 100
    categories = ["lateral_movement", "c2", "ipc", "stealth"]
    authors = ["Kevin Ross", "Gemini"]
    minimum = "1.3"
    evented = True
    ttps = ["T1559"]
    mbcs = ["E1559"]

    filter_apinames = {
        "CreateNamedPipeW", "CreateNamedPipeA", "NtCreateNamedPipeFile", 
        "CreateFileW", "CreateFileA", "CallNamedPipeW"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.pipe_creators = {} 
        self.ipc_events = []

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")
        proc_name = process.get("process_name", "unknown")

        pipe_name = self.get_argument(call, "FileName") or self.get_argument(call, "lpName") or self.get_argument(call, "Name")       
        if not pipe_name or not isinstance(pipe_name, str):
            return
            
        pipe_lower = pipe_name.lower()
        if "\\pipe\\" not in pipe_lower:
            return

        noisy_pipes = {"\\pipe\\lsass", "\\pipe\\samr", "\\pipe\\wkssvc", "\\pipe\\srvsvc", "\\pipe\\cng"}
        if any(noisy in pipe_lower for noisy in noisy_pipes):
            return

        if api in ("CreateNamedPipeW", "CreateNamedPipeA", "NtCreateNamedPipeFile"):
            if pipe_lower not in self.pipe_creators:
                self.pipe_creators[pipe_lower] = {"pid": pid, "name": proc_name}

        elif api in ("CreateFileW", "CreateFileA", "CallNamedPipeW"):
            if pipe_lower in self.pipe_creators:
                creator = self.pipe_creators[pipe_lower]

                if creator["pid"] != pid:
                    event = {
                        "pipe_name": pipe_name,
                        "server_process": f"{creator['name']} (PID: {creator['pid']})",
                        "client_process": f"{proc_name} (PID: {pid})"
                    }
                    
                    if event not in self.ipc_events:
                        self.ipc_events.append(event)
                        self.mark_call()
                        self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"ipc_named_pipe_communications": self.ipc_events})
        return self.ret

class InterProcessCommsMutex(Signature):
    name = "interprocess_comms_mutex"
    description = "Inter-process synchronization via mutexes, possibly for routing local C2 traffic or injection"
    severity = 3
    confidence = 100
    categories = ["lateral_movement", "c2", "ipc", "stealth"]
    authors = ["Kevin Ross", "Gemini"]
    minimum = "1.3"
    evented = True
    ttps = ["T1559"]
    mbcs = ["E1559"]

    filter_apinames = {
        "CreateMutexW", "CreateMutexA", "NtCreateMutant", 
        "OpenMutexW", "OpenMutexA"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.created_mutexes = {}
        self.ipc_events = []
        self.noisy_prefixes = {
            "\\basenamedobjects\\ctf", "\\basenamedobjects\\msctf",
            "\\sessions\\", "local\\zoneio", "global\\msdtc"
        }

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")
        proc_name = process.get("process_name", "unknown")
    

        mutex_name = self.get_argument(call, "Name") or self.get_argument(call, "MutexName") or self.get_argument(call, "ObjectName")        
        if not mutex_name or not isinstance(mutex_name, str):
            return
            
        mutex_lower = mutex_name.lower()

        if any(noisy in mutex_lower for noisy in self.noisy_prefixes):
            return

        if api in ("CreateMutexW", "CreateMutexA", "NtCreateMutant"):
            if mutex_lower not in self.created_mutexes:
                self.created_mutexes[mutex_lower] = {"pid": pid, "name": proc_name}
            else:
                creator = self.created_mutexes[mutex_lower]
                if creator["pid"] != pid:
                    self._record_ipc(mutex_name, pid, proc_name, creator)

        elif api in ("OpenMutexW", "OpenMutexA"):
            if mutex_lower in self.created_mutexes:
                creator = self.created_mutexes[mutex_lower]
                if creator["pid"] != pid:
                    self._record_ipc(mutex_name, pid, proc_name, creator)

    def _record_ipc(self, mutex_name, accessor_pid, accessor_name, creator):
        event = {
            "mutex_name": mutex_name,
            "creator_process": f"{creator['name']} (PID: {creator['pid']})",
            "accessor_process": f"{accessor_name} (PID: {accessor_pid})"
        }
        
        if event not in self.ipc_events:
            self.ipc_events.append(event)
            self.mark_call()
            self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"ipc_mutex_synchronization": self.ipc_events})
        return self.ret


class InterProcessCommsSharedMemory(Signature):
    name = "interprocess_comms_shared_memory"
    description = "Inter-process communication via named shared memory (file mappings), possibly for routing local C2 traffic or injection"
    severity = 3
    confidence = 100
    categories = ["lateral_movement", "c2", "ipc", "stealth"]
    authors = ["Kevin Ross", "Gemini"]
    minimum = "1.3"
    evented = True
    ttps = ["T1559"]
    mbcs = ["E1559"]

    filter_apinames = {
        "CreateFileMappingW", "CreateFileMappingA", "NtCreateSection",
        "OpenFileMappingW", "OpenFileMappingA", "NtOpenSection"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.created_sections = {}
        self.ipc_events = []

        self.noisy_prefixes = {
            "\\basenamedobjects\\cor_teb_", "\\basenamedobjects\\__comcatalogcache__",
            "\\basenamedobjects\\sxs", "\\basenamedobjects\\coremessaging",
            "\\basenamedobjects\\windows.ui", "\\sessions\\", "local\\sm0:"
        }

    def on_call(self, call, process):
        api = call["api"]
        pid = process.get("process_id")
        proc_name = process.get("process_name", "unknown")
        
        section_name = self.get_argument(call, "Name") or self.get_argument(call, "FileName") or self.get_argument(call, "ObjectAttributesName")
        if not section_name or not isinstance(section_name, str):
            return
            
        section_lower = section_name.lower()
        if any(noisy in section_lower for noisy in self.noisy_prefixes):
            return

        if "c:\\" in section_lower or "\\??\\c:\\" in section_lower:
            is_suspicious_mapping = False
            
            if section_lower.endswith(".exe") or section_lower.endswith(".bin") or section_lower.endswith(".tmp"):
                is_suspicious_mapping = True
                
            elif "\\users\\" in section_lower and any(p in section_lower for p in ("\\temp\\", "\\appdata\\", "\\downloads\\")):
                is_suspicious_mapping = True

            if not is_suspicious_mapping:
                return

        if api in ("CreateFileMappingW", "CreateFileMappingA", "NtCreateSection"):
            if section_lower not in self.created_sections:
                self.created_sections[section_lower] = {"pid": pid, "name": proc_name}
            else:
                creator = self.created_sections[section_lower]
                if creator["pid"] != pid:
                    self._record_ipc(section_name, pid, proc_name, creator)

        elif api in ("OpenFileMappingW", "OpenFileMappingA", "NtOpenSection"):
            if section_lower in self.created_sections:
                creator = self.created_sections[section_lower]

                if creator["pid"] != pid:
                    self._record_ipc(section_name, pid, proc_name, creator)

    def _record_ipc(self, section_name, accessor_pid, accessor_name, creator):
        event = {
            "shared_memory_name": section_name,
            "creator_process": f"{creator['name']} (PID: {creator['pid']})",
            "accessor_process": f"{accessor_name} (PID: {accessor_pid})"
        }
        
        if event not in self.ipc_events:
            self.ipc_events.append(event)
            self.mark_call()
            self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"ipc_shared_memory_transfers": self.ipc_events})
        return self.ret
