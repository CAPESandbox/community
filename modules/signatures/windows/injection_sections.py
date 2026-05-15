# Copyright (C) 2026 Kevin Ross
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


class SectionMappingInjection(Signature):
    name = "section_mapping_injection"
    description = "Maps a shared memory section into both the local and a remote process, possibly to inject code without using WriteProcessMemory"
    severity = 3
    confidence = 100
    categories = ["injection", "evasion", "stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]

    filter_apinames = {"NtMapViewOfSection", "MapViewOfFile"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.mapped_sections = {}
        self.injected_sections = []

    def on_call(self, call, process):
        section_handle = self.get_argument(call, "SectionHandle") or self.get_argument(call, "hFileMappingObject")
        process_handle = self.get_argument(call, "ProcessHandle") or self.get_argument(call, "hProcess")

        if section_handle and process_handle:
            sec_str = str(section_handle)
            proc_handle_str = str(process_handle)

            if sec_str not in self.mapped_sections:
                self.mapped_sections[sec_str] = set()

            self.mapped_sections[sec_str].add(proc_handle_str)
            has_local = any(h in ("-1", "0xffffffff", "0xffffffffffffffff") for h in self.mapped_sections[sec_str])
            has_remote = any(h not in ("-1", "0xffffffff", "0xffffffffffffffff") for h in self.mapped_sections[sec_str])
            if has_local and has_remote:
                proc_name = process.get("process_name", "unknown")
                self.injected_sections.append(f"Process {proc_name} mapped shared Section {sec_str} into a remote process")
                self.mark_call()
                self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"section_mapping_injections": self.injected_sections})
        return self.ret
