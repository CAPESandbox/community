# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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


class AntiVMCPU(Signature):
    name = "antivm_generic_cpu"
    description = "Checks the CPU name from registry, possibly for anti-virtualization"
    severity = 3
    categories = ["anti-vm"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1012", "T1057", "T1082", "T1497"]  # MITRE v6,7,8
    ttps += ["T1497.001"]  # MITRE v7,8
    ttps += ["U1332"]  # Unprotect
    mbcs = ["OB0001", "B0009", "B0009.005", "B0009.024", "OB0007", "E1082"]
    mbcs += ["OC0008", "C0036", "C0036.005"]  # micro-behaviour

    filter_apinames = set(
        [
            "RegQueryValueExW",
            "RegQueryValueExA",
            "NtQueryValueKey",
        ]
    )
    filter_categories = set(["registry"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.safe_proc_list = [
            "wordview.exe",
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "acrord32.exe",
            "acrord64.exe",
            "acrobat.exe",
        ]

    def on_call(self, call, process):
        if process["process_name"].lower() in self.office_proc_list:
            return False
        else:
            match = self.check_read_key(
                pattern=r".*\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\[^\\]+\\ProcessorNameString$", regex=True
            )
            if match:
                self.add_match(process, "registry", match)

    def on_complete(self):
        return self.has_matches()
