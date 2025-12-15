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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature


class MMCDotNetLoad(Signature):
    name = "mmc_dotnet_load"
    description = "Microsoft Management Console (MMC) loads .NET assembly or DLL"
    severity = 2
    categories = ["evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1218"]  # MITRE v6,7,8
    ttps += ["T1218.014"]  # MITRE v7,8

    filter_apinames = set(["LdrLoadDll"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.mmcproc = ["mmc.exe"]
        self.dotnetpaths = [
            r"[A-Z]:\\Windows\\assembly\\.*",
            r"[A-Z]:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL.*",
        ]

    def on_call(self, call, process):
        processname = process["process_name"]
        if processname:
            if processname.lower() in self.mmcproc:
                dllname = self.get_argument(call, "FileName")
                if dllname:
                    if "clr.dll" in dllname.lower():
                        if self.pid:
                            self.mark_call()
                        return True
                    else:
                        for dllpath in self.dotnetpaths:
                            if re.search(dllpath, dllname.lower(), re.IGNORECASE):
                                if self.pid:
                                    self.mark_call()
                                return True


class MMCDLLScriptLoad(Signature):
    name = "mmc_dll_script_load"
    description = "Microsoft Management Console (MMC) loads scripting engine DLL"
    severity = 2
    categories = ["evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1218"]  # MITRE v6,7,8
    ttps += ["T1218.014"]  # MITRE v7,8
    reference = "https://www.elastic.co/security-labs/grimresource"

    filter_apinames = set(["LdrLoadDll", "LdrGetDllHandle"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.mmcproc = ["mmc.exe"]
        self.script_dlls = {
            "jscript.dll",
            "vbscript.dll",
            "apds.dll",
            "msxml3.dll",
            "jscript9.dll",
        }

    def on_call(self, call, process):
        processname = process["process_name"]
        if processname:
            if processname.lower() in self.mmcproc:
                dllname = self.get_argument(call, "FileName")
                if dllname:
                    if any(dll in dllname.lower() for dll in self.script_dlls):
                        if self.pid:
                            self.mark_call()
                        return True
