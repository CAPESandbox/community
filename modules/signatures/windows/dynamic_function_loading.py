# CAPE - Config And Payload Extraction
# Copyright(C) 2018 redsand (redsand@redsand.net)
#
# This program is free software : you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature
import re

class dynamic_function_loading(Signature):
    name = "dynamic_function_loading"
    description = "Dynamic (imported) function loading detected"
    severity = 1
    confidence = 40
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["LdrGetProcedureAddress", "LdrLoadDll"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.dll_loaded = False
        self.loadctr = 0
        self.list = []

    def on_call(self, call, process):
        if call["api"] == "LdrLoadDll":
            self.dll_loaded = True
        elif self.dll_loaded and call["api"] == "LdrGetProcedureAddress":
            self.loadctr += 1
            self.data.append(
                {"DynamicLoader": "%s/%s" % (self.get_argument(call, "ModuleName"), self.get_argument(call, "FunctionName"))}
            )
            if self.pid:
                self.mark_call()

    def on_complete(self):
        if self.loadctr < 8:
            return False
        elif self.loadctr > 20:
            self.severity = 2
        return True


class MalformedDllLoading(Signature):
    name = "malformed_dll_loading"
    description = "Attempts to load a DLL with a heavily malformed name or decoded API name, indicative an error in the API hashing routine"
    severity = 3
    confidence = 40
    categories = ["evasion", "stealth"]
    authors = ["Kevin Ross", "Gemini"]
    minimum = "1.3"
    evented = True
    ttps = ["T1027"]

    filter_apinames = {"LdrGetDllHandle", "LdrLoadDll", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.malformed_dlls = set()
        
    def on_call(self, call, process):
        filename = self.get_argument(call, "FileName") or self.get_argument(call, "lpLibFileName")
        if not filename or not isinstance(filename, str):
            return
            
        # Check if the filename contains massive amounts of raw hex escapes (\x).
        # This occurs when CAPE dumps unprintable bytes that the malware accidentally passed.
        hex_escape_count = len(re.findall(r"\\x[0-9a-fA-F]{2,4}", filename))
        
        # Check if they accidentally passed known API strings to a DLL loader
        api_strings = ["Rtl", "NtQuery", "GetSystem", "MachinePreferred", "Filemark"]
        is_api_name = any(api in filename for api in api_strings) and (".dll" not in filename.lower())
        
        if hex_escape_count >= 4 or is_api_name:
            if filename not in self.malformed_dlls:
                self.malformed_dlls.add(filename)              
                self.mark_call()
                self.ret = True

    def on_complete(self):
        return self.ret
