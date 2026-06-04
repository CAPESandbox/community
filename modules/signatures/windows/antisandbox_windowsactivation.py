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

class AntiSandboxWindowsActivation(Signature):
    name = "antisandbox_windows_activation"
    description = "Queries Windows licensing, activation, or genuine status, possibly to detect unactivated sandbox or analysis environments."
    severity = 3
    confidence = 100
    categories = ["anti_sandbox", "evasion", "discovery"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1082", "T1497"] # System Information Discovery / Virtualization/Sandbox Evasion

    filter_apinames = {
        # 1. API Resolution & Direct SL Hooks
        "LdrGetProcedureAddress", "GetProcAddress",
        "SLIsGenuineLocal", "SLGetWindowsInformation",
        # 2. Registry Queries
        "NtQueryValueKey", "RegQueryValueExA", "RegQueryValueExW",
        # 3. WMI / COM Queries
        "IWbemServices_ExecQuery", "ExecQuery",
        # 4. Command Execution
        "CreateProcessInternalW", "NtCreateUserProcess", "ShellExecuteExW"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.activation_checks = set()

    def on_call(self, call, process):
        api = call["api"]

        if api in ("SLIsGenuineLocal", "SLGetWindowsInformation"):
            value_name = self.get_argument(call, "ValueName")
            if value_name:
                self.activation_checks.add("Called Licensing API directly: {0} ({1})".format(api, value_name))
            else:
                self.activation_checks.add("Called Licensing API directly: {0}".format(api))
            self.mark_call()
            self.ret = True

        elif api in ("LdrGetProcedureAddress", "GetProcAddress"):
            func_name = self.get_argument(call, "FunctionName") or self.get_argument(call, "lpProcName")
            if func_name:
                func_lower = func_name.lower()
                
                if func_lower in ("slisgenuinelocal", "slgetwindowsinformation", "slgetwindowsinformationdword", "slgetlicensingstatusinfo"):
                    self.activation_checks.add("Resolved Licensing API: {0}".format(func_name))
                    self.mark_call()
                    self.ret = True

        elif api in ("NtQueryValueKey", "RegQueryValueExA", "RegQueryValueExW"):
            key_name = self.get_argument(call, "FullName") or self.get_argument(call, "ValueName")
            if key_name:
                key_lower = key_name.lower()
                
                if "softwareprotectionplatform" in key_lower or "wpa\\events" in key_lower or "security-spp-genuinelocalstatus" in key_lower:
                    self.activation_checks.add("Queried Licensing Value/Registry: {0}".format(key_name))
                    self.mark_call()
                    self.ret = True

        elif api in ("IWbemServices_ExecQuery", "ExecQuery"):
            query = self.get_argument(call, "Query")
            if query:
                query_lower = query.lower()
                
                if "softwarelicensingproduct" in query_lower or "softwarelicensingservice" in query_lower:
                    self.activation_checks.add("WMI Licensing Query: {0}".format(query))
                    self.mark_call()
                    self.ret = True

        elif api in ("CreateProcessInternalW", "NtCreateUserProcess", "ShellExecuteExW"):
            cmdline = self.get_argument(call, "CommandLine") or self.get_argument(call, "lpCommandLine") or self.get_argument(call, "lpFile")
            if cmdline:
                cmd_lower = cmdline.lower()
                
                if "slmgr" in cmd_lower or "slmgr.vbs" in cmd_lower:
                    self.activation_checks.add("Executed Licensing Script: {0}".format(cmdline))
                    self.mark_call()
                    self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"activation_checks": list(self.activation_checks)})
        return self.ret
