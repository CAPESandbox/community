# Copyright (C) 2024 Kevin Ross
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


class AntiVMChecksAvailableMemory(Signature):
    name = "antivm_checks_available_memory"
    description = "Checks available memory"
    severity = 1
    categories = ["antivm"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1082"]  # MITRE v6,7,8
    confidence = 30

    filter_apinames = set(["GlobalMemoryStatusEx"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.process_safelist = ["microsoftedgeupdate.exe", "winword.exe"]

    def on_call(self, call, process):
        if process.get("process_name", "").lower() in self.process_safelist:
            return False
        self.mark_call()
        self.ret = True

    def on_complete(self):
        return self.ret
