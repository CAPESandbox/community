# Copyright (C) 2023 Kevin Ross
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


class DLLArchiveExecution(Signature):
    name = "dll_archive_execution"
    description = "Executes a DLL from within an archive file"
    severity = 2
    confidence = 100
    categories = ["command"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1553", "T1105"]  # MITRE v6,7,8

    def run(self):
        ret = False
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if ("rundll32" in lower or "regsvr32" in lower) and (".iso\\" in lower or ".img\\" in lower or ".zip\\" in lower):
                ret = True
                self.data.append({"command": cmdline})

        return ret


class LNKArchiveExecution(Signature):
    name = "lnk_archive_execution"
    description = "Executes a LNK file from within an archive file"
    severity = 3
    confidence = 100
    categories = ["command"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1204", "T1553"]  # MITRE v6,7,8

    def run(self):
        ret = False
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if (".iso\\" in lower or ".img\\" in lower or ".zip\\" in lower) and ".lnk" in lower:
                ret = True
                self.data.append({"command": cmdline})

        return ret


class ScriptArchiveExecution(Signature):
    name = "script_archive_execution"
    description = "Executes a scipt from within an archive file"
    severity = 3
    confidence = 100
    categories = ["command"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1553", "T1105"]  # MITRE v6,7,8

    def run(self):
        ret = False
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if ("wscript" in lower or "jscript" in lower or "cscript" in lower or "mshta" in lower) and (
                ".iso\\" in lower or ".img\\" in lower or ".zip\\" in lower
            ):
                ret = True
                self.data.append({"command": cmdline})

        return ret
