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

class RansomwareAttributeStripping(Signature):
    name = "ransomware_attribute_stripping"
    description = "Strips file attributes to bypass read-only restrictions on a large number of files, possibly prior to ransomware/wiper destruction"
    severity = 3
    confidence = 50
    categories = ["ransomware", "wiper"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1486"]

    filter_apinames = {"NtSetInformationFile", "SetFileAttributesA", "SetFileAttributesW", "SetFileAttributesExW"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.stripped_files = set()

    def on_call(self, call, process):
        filepath = None
        
        if call["api"] == "NtSetInformationFile":
            info_class = self.get_argument(call, "FileInformationClass")
            if info_class == 4 or str(info_class) == "4":  
                file_info = self.get_argument(call, "FileInformation")
                # 0x80 is the bitmask for FILE_ATTRIBUTE_NORMAL
                if isinstance(file_info, str) and "\\x80\\x00\\x00\\x00" in file_info:
                    filepath = self.get_argument(call, "HandleName")
                    
        elif call["api"].startswith("SetFileAttributes"):
            attrs = self.get_argument(call, "FileAttributes")
            try:
                attrs_val = int(attrs, 16) if isinstance(attrs, str) and attrs.startswith("0x") else int(attrs)
                if attrs_val == 128:  # 128 is decimal for 0x80
                    filepath = self.get_argument(call, "FileName")
            except (ValueError, TypeError):
                pass

        if isinstance(filepath, str) and "\\" in filepath:
            filepath_lower = filepath.lower()
            if filepath_lower not in self.stripped_files:
                self.stripped_files.add(filepath_lower)
                if len(self.stripped_files) <= 10:
                    self.mark_call()

    def on_complete(self):
        ret = False
        if len(self.stripped_files) > 30:
            self.data.append({
                "total_files_stripped": len(self.stripped_files),
            })
            ret = True

        return ret


class MassFileModificationAccess(Signature):
    name = "mass_file_modification_access"
    description = "Opens a large number of files requesting WRITE or DELETE access, indicative of ransomware/wipers"
    severity = 3
    confidence = 50
    categories = ["ransomware", "wiper"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1486", "T1485"]

    filter_apinames = {"NtOpenFile"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.targeted_files = set()
        self.example_file = None
        self.dangerous_strings = ("WRITE", "DELETE", "MAXIMUM_ALLOWED", "GENERIC_ALL")

    def on_call(self, call, process):
        pretty_access = ""
        for arg in call.get("arguments", []):
            if arg.get("name") in ("DesiredAccess", "Access"):
                pretty_access = arg.get("pretty_value", "")
                if not pretty_access:
                    pretty_access = str(arg.get("value", ""))
                break
                
        pretty_access = pretty_access.upper()       
        if not any(flag in pretty_access for flag in self.dangerous_strings):
            return

        filepath = self.get_argument(call, "FileName") or self.get_argument(call, "HandleName")
        if isinstance(filepath, str) and "\\" in filepath:
            filepath_lower = filepath.lower()
            # Ignore raw devices, named pipes, and typical volume queries
            if "\\??\\" in filepath_lower or "\\device\\" in filepath_lower:
                return

            if filepath_lower not in self.targeted_files:                   
                self.targeted_files.add(filepath_lower)
                if len(self.targeted_files) <= 15:
                    self.mark_call()

    def on_complete(self):
        ret = False
        if len(self.targeted_files) > 40:
            self.data.append({
                "total_existing_files_opened_for_modification": len(self.targeted_files),
            })
            ret = True

        return ret
