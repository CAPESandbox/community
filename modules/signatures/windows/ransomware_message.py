# Copyright (C) 2016 Kevin Ross
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

try:
    import re2 as re
except ImportError:
    import re

class RansomwareMessage(Signature):
    name = "ransomware_message"
    description = "Writes a potential ransom message to disk"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross", "bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1486"]
    mbcs = ["OB0008", "E1486", "OC0001", "C0016"]

    filter_apinames = {"NtWriteFile"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        
        self.indicators = [
            "your files", "your data", "your documents", "restore files",
            "restore data", "restore the files", "restore the data",
            "recover files", "recover data", "recover the files",
            "recover the data", "has been locked", "pay fine",
            "pay a fine", "pay the fine", "decrypt", "encrypt",
            "recover them", "recover your", "recover personal",
            "bitcoin", "secret server", "secret internet server",
            "install tor", "download tor", "tor browser", "tor gateway",
            "tor-browser", "tor-gateway", "torbrowser", "torgateway",
            "torproject.org", "tox.chat", "ransom", "bootkit", "rootkit",
            "payment", "victim", "AES128", "AES256", "AES 128", "AES 256",
            "AES-128", "AES-256", "RSA1024", "RSA2048", "RSA4096",
            "RSA 1024", "RSA 2048", "RSA 4096", "RSA-1024", "RSA-2048",
            "RSA-4096", "private key", "personal key", "your code",
            "private code", "personal code", "enter code", "your key",
            "unique key", "your database", "encrypted", "bit coin",
            "BTC", "ethereum", "what happened", "what happened",
            "decryptor", "decrypter", "personal ID", "unique ID",
            "encryption ID", "device ID", "hardwareid", "recover my",
            "wallet address", "localbitcoins", "Attention!",
            "restore the system", "restore system", "military grade encryption",
            "personal identifier", "personal identification code",
            "get back my", "get back your", "your network"
        ]
        
        indicators_bytes = [i.encode('utf-8').lower() for i in self.indicators]
        pattern_bytes = b"|".join(re.escape(i) for i in indicators_bytes)
        self.regex = re.compile(pattern_bytes)

    def on_call(self, call, process):
        filepath = self.get_argument(call, "HandleName")
        
        if not filepath:
            return
            
        filepath_lower = filepath.lower()
        
        is_target_path = (
            filepath_lower == "\\??\\physicaldrive0" or 
            filepath_lower.startswith("\\device\\harddisk") or 
            filepath_lower.endswith((".txt", ".html", ".hta", ".rtf")) or
            "readme" in filepath_lower or 
            "read_me" in filepath_lower or
            "decrypt" in filepath_lower
        )
        
        if not is_target_path:
            return

        buff = self.get_raw_argument(call, "Buffer")
        if buff and len(buff) >= 128:
            buff_lower = buff.lower()
            matches = set(self.regex.findall(buff_lower))
        
            if len(matches) > 1:
                self.data.append({"ransom_note": filepath})
                self.data.append({"beginning_of_ransom_message": buff})
            
                if self.pid:
                    self.mark_call()
                self.ret = True

    def on_complete(self):
        if not self.ret and "dropped" in self.results:
            for dropped in self.results["dropped"]:
                
                raw_name = dropped.get("name", "")
                if isinstance(raw_name, list) and len(raw_name) > 0:
                    filename = str(raw_name[0]).lower()
                else:
                    filename = str(raw_name).lower()
                
                if filename.endswith((".txt", ".html", ".hta", ".rtf")) or "read_me" in filename or "readme" in filename:
                    filedata = dropped.get("data")
                    
                    if isinstance(filedata, str):
                        filedata = filedata.encode('utf-8', errors='ignore')
                        
                    if filedata and len(filedata) >= 128:
                        filedata_lower = filedata.lower()
                        matches = set(self.regex.findall(filedata_lower))

                        if len(matches) > 1:
                            self.data.append({"ransom_note": filename})
                            self.data.append({"beginning_of_ransom_message": filedata})
                            self.ret = True
                            break

        return self.ret
