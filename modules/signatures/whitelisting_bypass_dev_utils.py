# Copyright (C) 2020 ditekshen
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

class PersistsDotNetDevUtility(Signature):
    name = "persists_dev_util"
    description = "Attempts to bypass application whitelisting by copying and persisting .NET utility"
    severity = 3
    categories = ["masquerading", "evasion", "execution", "dotnet"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttp = ["T1118", "T1127"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.devtools = [
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\RegAsm\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\MSBuild\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\RegSvcs\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\InstallUtil\.exe", re.IGNORECASE),
        ]
        self.sname = str()
        self.dname = str()
    
    filter_apinames = set(["CopyFileA", "CopyFileW", "CopyFileExW", "RegSetValueExA", "RegSetValueExW"])

    def on_call(self, call, process):
        if call["api"].startswith("CopyFile"):
            self.sname = self.get_argument(call, "ExistingFileName").lower()
            if self.sname:
                for tool in self.devtools:
                    if re.search(tool, self.sname):
                        self.dname = self.get_argument(call, "NewFileName").lower()

        if call["api"] == "RegSetValueExA" or call["api"] == "RegSetValueExW":
            buff = self.get_argument(call, "Buffer").lower()
            if buff and self.dname:
                if self.dname in buff:
                    self.data.append({"Copy": self.sname + " > " + self.dname})
                    fname = self.get_argument(call, "FullName")
                    if fname:
                        self.data.append({"Regkey": fname})

    def on_complete(self):
        if len(self.data) > 0:
            return True

        return False

class SpwansDotNetDevUtiliy(Signature):
    name = "spawns_dev_util"
    description = "Attempts to bypass application whitelisting"
    severity = 3
    categories = ["masquerading", "evasion", "execution", "dotnet"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttp = ["T1118", "T1127"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.devtools = [
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\RegAsm\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\MSBuild\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\RegSvcs\.exe", re.IGNORECASE),
            re.compile("[A-Za-z]:\\\\Windows\\\\Microsoft\.NET\\\\Framework\\\\v.*\\\\InstallUtil\.exe", re.IGNORECASE),
        ]
        self.sname = str()
        self.dname = str()
        self.executecopy = False
    
    filter_apinames = set(["CreateProcessInternalA", "CreateProcessInternalW", "CopyFileA", "CopyFileW", "CopyFileExW"])

    def on_call(self, call, process):
        if call["api"].startswith("CopyFile"):
            self.sname = self.get_argument(call, "ExistingFileName").lower()
            if self.sname:
                for tool in self.devtools:
                    if re.search(tool, self.sname):
                        self.dname = self.get_argument(call, "NewFileName").lower()

        if call["api"] == "CreateProcessInternalA" or call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
            appname = self.get_argument(call, "ApplicationName")
            if cmdline:
                flags = int(self.get_argument(call, "CreationFlags"), 16)
                # CREATE_SUSPENDED or CREATE_SUSPENDED|CREATE_NO_WINDOW
                if flags & 0x4 or flags & 0x08000004:
                    for tool in self.devtools:
                        if "{path}" in cmdline:
                            appname = self.get_argument(call, "ApplicationName")
                            if appname:
                                if re.search(tool, appname):
                                    procname = process["process_name"]
                                    self.data.append({"Process": procname + " > " + appname})
                        elif self.dname and self.dname in cmdline:
                            self.executecopy = True
                            procname = process["process_name"]
                            self.data.append({"Copy": self.sname + " > " + self.dname})
                            self.data.append({"Process": procname + " > " + self.dname})
                        elif re.search(tool, cmdline):
                            procname = process["process_name"]
                            spawnapp = self.get_argument(call, "ApplicationName")
                            if not spawnapp:
                                spawnapp = cmdline
                            self.data.append({"Process": procname + " > " + spawnapp})

    def on_complete(self):
        if len(self.data) > 0:
            if self.executecopy:
                self.description = "{0} {1}".format(self.description, "by copying and executing .NET utility in a suspended state, potentially for injection")
            else:
                self.description = "{0} {1}".format(self.description, "by executing .NET utility in a suspended state, potentially for injection")
            return True

        return False