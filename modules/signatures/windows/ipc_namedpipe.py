# Copyright (C) 2016 KillerInstinct
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


class IPC_NamedPipe(Signature):
    name = "ipc_namedpipe"
    description = "A named pipe was used for inter-process communication"
    severity = 2
    categories = ["generic"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True
    mbcs = ["OC0006", "C0003", "C0003.001"]  # micro-behaviour

    filter_apinames = set(["NtCreateNamedPipeFile", "NtReadFile", "NtWriteFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.created = dict()
        self.ipc = dict()
        self.pipeNames = set()

    def on_call(self, call, process):
        # We only need to process "good" returns.
        if call["status"]:
            if call["api"] == "NtCreateNamedPipeFile":
                name = self.get_argument(call, "PipeName").split("\\")[-1]
                # Ignore attempted "blank" pipe names
                if name:
                    self.pipeNames.add(name)
                    self.created[name] = process["process_id"]
                    if self.pid:
                        self.mark_call()

            elif call["api"] == "NtReadFile" or call["api"] == "NtWriteFile":
                handle = self.get_argument(call, "HandleName")
                # Here we need to handle the case where a child process
                # creates the pipe. We'd prefer to just add the pipe when it's
                # it's created, however cuckoo only sees API logs one process
                # at a time. For now we will just work around the issue by
                # adding previously unseen pipes during a read/write.
                if handle.startswith("\\Device\\NamedPipe\\"):
                    self.pipeNames.add(handle.split("\\")[-1])
                if self.pipeNames:
                    for name in self.pipeNames:
                        if handle == "\\Device\\NamedPipe\\" + name:
                            if name not in self.ipc:
                                self.ipc[name] = dict()
                            pid = process["process_id"]
                            if pid not in self.ipc[name]:
                                self.ipc[name][pid] = set()
                            if call["api"] == "NtReadFile":
                                self.ipc[name][pid].add("reads")
                                if self.pid:
                                    self.mark_call()
                            elif call["api"] == "NtWriteFile":
                                self.ipc[name][pid].add("writes")
                                if self.pid:
                                    self.mark_call()

    def on_complete(self):
        ret = False
        ipcs = list()
        if self.ipc and self.created:
            for ipc in self.created.keys():
                if ipc in self.ipc:
                    ipcs.append(ipc)

        if ipcs:
            for ipc in ipcs:
                # Check if more than one pid interacted with a pipe
                if len(self.ipc[ipc]) > 1:
                    ret = True
                    desc = "{0}({1}) Created Named Pipe {2}".format(
                        self.get_name_from_pid(str(self.created[ipc])), self.created[ipc], ipc
                    )
                    self.data.append({"Creates": desc})
                    for pid in self.ipc[ipc]:
                        desc = "{0}({1}) {2} data to Named Pipe {3}".format(
                            self.get_name_from_pid(str(pid)), pid, "/".join(self.ipc[ipc][pid]), ipc
                        )
                        self.data.append({"Interacts": desc})

        return ret

class EscalatePrivilegeViaNamedPipe(Signature):
    name = "escalate_privilege_via_named_pipe"
    description = "Attempts to escalate privilege via named pipe"
    severity = 3
    categories = ["bypass"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1134"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/privilege_escalation_privilege_escalation_via_named_pipe_impersonation.toml"]

    filter_apinames = set(["CreateProcessInternalW"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()

        # Checking parent process for false positives.
        if pname in ["chrome.exe", "msedge.exe"] and call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine")
            lower = cmdline.lower()
            if (any(process in lower for process in ["cmd.exe", "powershell.exe", "sc.exe", "schtasks.exe"])
                    and "\\\\.\\pipe\\" in lower):
                return False

    def on_complete(self):
        cmdlines = self.results.get("behavior").get("summary").get("executed_commands")
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if (any(process in lower for process in ["cmd.exe", "powershell.exe", "sc.exe", "schtasks.exe"])
                    and "\\\\.\\pipe\\" in lower):
                return True
        return False