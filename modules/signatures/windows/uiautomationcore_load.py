# Copyright (C) 2025 bartblaze
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

class UIAutomationCoreLoad(Signature):
    name = "uiautomationcore_load"
    description = "Process loads UIAutomationCore.dll, potentially for evasion or execution."
    severity = 1  # experimental rule, sev 1
    categories = ["evasion", "execution"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    reference = "https://www.akamai.com/blog/security-research/windows-ui-automation-attack-technique-evades-edr#abusing" 

    filter_apinames = set(["LdrLoadDll", "LdrGetDllHandle"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.target = "uiautomationcore.dll"
        self.fp_excluded_procs = set([
            "explorer.exe",
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "chrome.exe",
            "msedge.exe",
            "firefox.exe",
            "dwm.exe",
            "services.exe",
            "sihost.exe",
        ])

    def on_call(self, call, process):
        pname = (process.get("process_name") or "").lower()
        if pname in self.fp_excluded_procs:
            return

        dllname = (self.get_argument(call, "FileName") or "").lower()
        if self.target in dllname:
            if self.pid:
                self.mark_call()
            return True
