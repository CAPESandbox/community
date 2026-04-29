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


class CryptGenKey(Signature):
    name = "generates_crypto_key"
    description = "Uses Windows APIs to generate a cryptographic key"
    severity = 1
    # Migrated by @CybercentreCanada
    authors = ["Kevin Ross", "@CybercentreCanada"]
    minimum = "1.2"
    evented = True
    mbcs = ["OC0005", "C0028"]

    filter_apinames = set(["CryptGenKey", "CryptExportKey"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.process_safelist = ["powershell.exe", "winword.exe", "powerpnt.exe", "excel.exe"]

    def on_call(self, _, process):
        if process["process_name"] in self.process_safelist:
            return False
        if self.pid:
            self.mark_call()
        return True


class QueryFipsReconnaissance(Signature):
    name = "query_fips_reconnaissance"
    description = "Queried the FIPS cryptography policy, can be used to adapt C2 network encryption or by legitimate encryption software"
    severity = 2
    confidence = 50
    categories = ["discovery", "c2"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1082", "T1008"]

    filter_apinames = {
        "NtOpenKey", "NtOpenKeyEx", "NtQueryValueKey", "RegQueryValueExA", "RegQueryValueExW"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.fips_events = set()

    def on_call(self, call, process):
        key_name = self.get_argument(call, "FullName") or self.get_argument(call, "ObjectAttributes") or ""
        
        if "lsa\\fipsalgorithmpolicy" in str(key_name).lower():
            proc_name = process.get("process_name", "unknown")
            pid = process.get("process_id", "unknown")
            
            event_msg = "{} (PID: {}) probed FIPS encryption policy at '{}'".format(proc_name, pid, key_name)
            
            if event_msg not in self.fips_events:
                self.fips_events.add(event_msg)
                self.mark_call()
                self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"behavioral_fips_reconnaissance": list(self.fips_events)})
        return self.ret
