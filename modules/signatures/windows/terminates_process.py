# Copyright (C) 2017 Kevin Ross
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


class TerminatesRemoteProcess(Signature):
    name = "terminates_remote_process"
    description = "Terminates another process"
    severity = 2
    categories = ["persistence", "stealth"]
    # Migrated by @CybercentreCanada
    authors = ["Kevin Ross", "@CybercentreCanada"]
    minimum = "1.2"
    mbcs = ["C0018"]
    evented = True
    confidence = 60
    safelistprocs = [
        "svchost.exe",
        "microsoftedgeupdate.exe",
        "acrobat.exe",
        "acrocef.exe",
        "services.exe",
    ]

    filter_apinames = set(["NtTerminateProcess"])

    def on_call(self, call, _):
        if self.get_argument(call, "ProcessHandle") not in ["0xffffffff", "0xffffffffffffffff", "0x00000000", "0x0000000000000000"]:
            if self.pid:
                process_name = self.get_name_from_pid(self.pid).lower()
                if process_name not in self.safelistprocs:
                    self.mark_call()
                    self.data.append({"process": self.get_name_from_pid(self.pid)})

    def on_complete(self):
        if self.data:
            return True
        else:
            return False
