# Copyright (C) 2026 Kevin Ross, created with assistance from Gemini
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

class AmsiEnumeration(Signature):
    name = "amsi_enumeration"
    description = "Enumerated Anti-Malware Scan Interface (AMSI) providers, a potential precursor to AMSI bypass or EDR unhooking"
    severity = 3
    confidence = 40    
    categories = ["discovery", "defense_evasion"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1518", "T1562"]

    filter_apinames = {
        "NtOpenKey", "NtOpenKeyEx", "RegOpenKeyExA", "RegOpenKeyExW", 
        "RegEnumKeyExA", "RegEnumKeyExW", "RegQueryValueExA", "RegQueryValueExW"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.amsi_events = set()

    def on_call(self, call, process):
        # Extract the registry key being queried directly
        key_name = self.get_argument(call, "FullName") or self.get_argument(call, "ObjectAttributes") or self.get_argument(call, "SubKey") or ""
        
        if "software\\microsoft\\amsi" in str(key_name).lower():
            proc_name = process.get("process_name", "unknown")
            pid = process.get("process_id", "unknown")
            event_msg = f"{proc_name} (PID: {pid}) probed AMSI registry '{key_name}'"
            
            if event_msg not in self.amsi_events:
                self.amsi_events.add(event_msg)
                self.mark_call()
                self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"amsi_enumeration": list(self.amsi_events)})
        return self.ret
