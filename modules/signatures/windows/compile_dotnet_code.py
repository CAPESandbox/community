# Copyright (C) 2022 ditekshen
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


class CompilesDotNetCode(Signature):
    name = "dotnet_code_compile"
    description = "Compiles .NET code into an executable and executes it"
    severity = 3
    categories = ["evasion", "execution", "dropper", "dotnet", "exploit", "office"]
    authors = ["ditekshen", "Zane C. Bowers-Hadley"]
    minimum = "1.3"
    evented = True
    ttps = ["T1500"]  # MITRE v6
    ttps += ["T1027"]  # MITRE v6,7,8
    ttps += ["T1027.004"]  # MITRE v7,8
    mbcs = ["OB0002", "E1027"]

    filter_apinames = set(["CreateProcessInternalA", "CreateProcessInternalW", "NtWriteFile", "NtCreateUserProcess"])
    filter_analysistypes = set(["file"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.data = []
        self.csccmd = False
        self.cvtrescmd = False
        self.writemz = False

    def on_call(self, call, process):
        if (
            call["api"] == "CreateProcessInternalA"
            or call["api"] == "CreateProcessInternalW"
            or call["api"] == "NtCreateUserProcess"
        ):
            cmdline = self.get_argument(call, "CommandLine")
            if cmdline:
                if "csc.exe" in cmdline or "vbc.exe" in cmdline:
                    self.csccmd = True
                    self.data.append({"command": cmdline})

        processname = process["process_name"].lower()
        if processname == "csc.exe" or processname == "vbc.exe":
            if (
                call["api"] == "CreateProcessInternalA"
                or call["api"] == "CreateProcessInternalW"
                or call["api"] == "NtCreateUserProcess"
            ):
                cmdline = self.get_argument(call, "CommandLine")
                if cmdline:
                    if "cvtres.exe" in cmdline:
                        self.cvtrescmd = True
                        self.data.append({"command": cmdline})

            if call["api"] == "NtWriteFile":
                buff = self.get_argument(call, "Buffer")
                if buff:
                    if buff.startswith("MZ"):
                        self.writemz = True

    def on_complete(self):
        match = False
        expscore = 0
        indicators = [
            ".*\.pdb",
            ".*\.(cs|CS)",
            ".*\.(vb|VB)",
            ".*\.cmdline",
            ".*\.(dll|DLL)",
            ".*\.(exe|EXE)",
            ".*\.(tmp|TMP)",
        ]

        if (self.csccmd or self.cvtrescmd) and self.writemz:
            for indicator in indicators:
                for dropped in self.results.get("dropped", []):
                    for filename in dropped.get("name", []):
                        if re.match(indicator, filename, re.IGNORECASE):
                            match = True
                            if filename.endswith(".pdb") or "Logo." in filename:
                                expscore += 1
                            for filepath in dropped["guest_paths"]:
                                if filename.endswith(".tmp") or filename.endswith(".TMP"):
                                    if "COFF" in dropped["type"] or "MSVC" in dropped["type"]:
                                        self.data.append({"file": filepath})
                                else:
                                    self.data.append({"file": filepath})

            if match and self.results["info"]["package"] in ["doc", "xls", "ppt"] and expscore >= 2:
                self.description += " potentially via exploiting CVE-2017-8759"
                return True
            elif match:
                return True

        return False
