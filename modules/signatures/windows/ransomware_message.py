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

    filter_apinames = {"NtWriteFile", "WriteFile"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

        self.indicators = [
            ".onion",
            "aes 128",
            "aes 256",
            "aes-128",
            "aes-256",
            "aes128",
            "aes256",
            "all data",
            "attention!",
            "bit coin",
            "bitcoin",
            "bootkit",
            "btc",
            "decrypt",
            "decrypter",
            "decryptor",
            "device id",
            "download tor",
            "encrypt",
            "encrypted",
            "encryption id",
            "enter code",
            "ethereum",
            "get back my",
            "get back your",
            "hardwareid",
            "has been locked",
            "install tor",
            "localbitcoins",
            "military grade encryption",
            "pay a fine",
            "pay fine",
            "pay the fine",
            "payment",
            "personal code",
            "personal id",
            "personal identification code",
            "personal identifier",
            "personal key",
            "private code",
            "private key",
            "ransom",
            "recover data",
            "recover files",
            "recover my",
            "recover personal",
            "recover the data",
            "recover the files",
            "recover them",
            "recover your",
            "restore data",
            "restore files",
            "restore system",
            "restore the data",
            "restore the files",
            "restore the system",
            "rootkit",
            "rsa 1024",
            "rsa 2048",
            "rsa 4096",
            "rsa-1024",
            "rsa-2048",
            "rsa-4096",
            "rsa1024",
            "rsa2048",
            "rsa4096",
            "secret internet server",
            "secret server",
            "tor browser",
            "tor gateway",
            "tor-browser",
            "tor-gateway",
            "torbrowser",
            "torgateway",
            "torproject.org",
            "tox.chat",
            "unique id",
            "unique key",
            "victim",
            "wallet address",
            "what happened",
            "your code",
            "your data",
            "your database",
            "your documents",
            "your files",
            "your key",
            "your network"
        ]

        indicators_str = [re.escape(i.lower()) for i in self.indicators]
        pattern_str = "|".join(indicators_str)
        self.regex = re.compile(pattern_str)

    def on_call(self, call, process):
        filepath = self.get_argument(call, "HandleName") or self.get_argument(call, "FileName")
        
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

        buff = self.get_argument(call, "Buffer")
        
        if buff:
            if isinstance(buff, bytes) or isinstance(buff, bytearray):
                buff_str = bytes(buff).decode('utf-8', errors='ignore')
            else:
                buff_str = str(buff)

            if len(buff_str) >= 32:
                buff_lower = buff_str.lower()
                matches = set(self.regex.findall(buff_lower))
            
                if len(matches) > 1:
                    self.mark_call()
                    return True

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
                    
                    if filedata:
                        if isinstance(filedata, bytes) or isinstance(filedata, bytearray):
                            filedata_str = bytes(filedata).decode('utf-8', errors='ignore')
                        else:
                            filedata_str = str(filedata)
                            
                        if len(filedata_str) >= 32:
                            filedata_lower = filedata_str.lower()
                            matches = set(self.regex.findall(filedata_lower))

                            if len(matches) > 1:
                                self.data.append({"ransom_note": filename})
                                self.data.append({"beginning_of_ransom_message": filedata_str})
                                self.ret = True
                                break

        return self.ret


class MassRansomNoteDrop(Signature):
    name = "mass_ransom_note_drop"
    description = "Writes or copies the same ransom note filename across multiple directories"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1486"]
    mbcs = ["OB0008", "E1486"]

    filter_apinames = set([
        "NtWriteFile", "WriteFile", 
        "CopyFileA", "CopyFileW", "CopyFileExA", "CopyFileExW",
        "MoveFileA", "MoveFileW", "MoveFileExA", "MoveFileExW"
    ])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.marked_calls = 0
        self.dropped_notes = {}
        self.note_keywords = ("readme", "read_me", "decrypt", "restore", "instructions", "recover")
        self.extensions = (".txt", ".html", ".hta", ".rtf", ".url")

    def on_call(self, call, process):
        pid = process.get("process_id")

        filepath = self.get_argument(call, "NewFileName") or self.get_argument(call, "HandleName") or self.get_argument(call, "FileName")

        if not isinstance(filepath, str):
            return

        filepath = filepath.replace("/", "\\")
        if "\\" not in filepath:
            return

        dirname, _, filename = filepath.rpartition("\\")
        filename_lower = filename.lower()
        
        if not filename_lower.endswith(self.extensions):
            return

        if not any(kw in filename_lower for kw in self.note_keywords):
            return

        dirname_lower = dirname.lower()

        if pid not in self.dropped_notes:
            self.dropped_notes[pid] = {}

        if filename_lower not in self.dropped_notes[pid]:
            self.dropped_notes[pid][filename_lower] = set()

        if dirname_lower in self.dropped_notes[pid][filename_lower]:
            return

        self.dropped_notes[pid][filename_lower].add(dirname_lower)
        dir_count = len(self.dropped_notes[pid][filename_lower])

        if dir_count >= 2 and self.marked_calls < 5:
            self.mark_call()
            self.marked_calls += 1

        if dir_count >= 5:
            self.ret = True

    def on_complete(self):
        if self.ret:
            for pid, notes in self.dropped_notes.items():
                for note_name, dirs in notes.items():
                    if len(dirs) >= 5:
                        self.data.append({
                            "ransom_note": note_name,
                            "pid": pid,
                            "directories_count": len(dirs)
                        })
        return self.ret
