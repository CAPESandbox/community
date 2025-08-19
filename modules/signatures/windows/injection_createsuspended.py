# Copyright (C) 2025 Kevin Ross
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

class CreatesSuspendedProcess(Signature):
    name = "creates_suspended_process"
    description = "Creates a process in a suspended state, likely for injection"
    severity = 2
    confidence = 50
    categories = ["injection", "process hollowing"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True
    ttps = ["T1055"]  # MITRE v6,7,8

    filter_apinames = set(["CreateProcessInternalA", "CreateProcessInternalW"])

    def on_call(self, call, process):
        CREATE_SUSPENDED = 0x4
        creation_flags_str = self.get_argument(call, "CreationFlags")
        if creation_flags_str:
            try:
                flags = int(creation_flags_str, 16)
                if flags & CREATE_SUSPENDED:
                    self.mark_call()
            except ValueError:
                # Ignore if the argument is not a valid integer.
                pass
    def on_complete(self):
        return self.has_marks()
