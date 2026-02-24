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

class RansomwareSetsIcon(Signature):
    name = "ransomware_sets_icon"
    description = "Modifies registry keys for file-extension hijacking, possible ransomware behavior"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1486", "T1564"] 
    mbcs = ["OB0008", "E1486"]

    filter_apinames = {"RegSetValueExA", "RegSetValueExW"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        
    def on_call(self, call, process):
        filepath = self.get_argument(call, "Buffer")         
        regkey = self.get_argument(call, "FullName")
        
        if isinstance(filepath, str) and isinstance(regkey, str):
            filepath_lower = filepath.lower()
            regkey_lower = regkey.lower()
            
            is_icon_hijack = filepath_lower.endswith(".ico") and (r"\defaulticon" in regkey_lower or r"\applications" in regkey_lower)
            is_userchoice_hijack = r"\userchoice" in regkey_lower
            
            if is_icon_hijack or is_userchoice_hijack:
                self.mark_call()
                self.ret = True

    def on_complete(self):
        return self.ret
