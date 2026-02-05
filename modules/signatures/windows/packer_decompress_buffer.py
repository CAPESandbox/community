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

class DecompressEXE(Signature):
    name = "decompress_exe"
    description = "Decompresses an executable in memory, may be indicative of a packer or manual loader"
    severity = 2
    confidence = 50
    categories = ["packer"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    enabled = True
    ttps = ["T1027", "T1027.002", "T1620"] 
    mbcs = ["B0002", "F0001", "OB0006"]

    filter_apinames = set(["RtlDecompressBuffer"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    def on_call(self, call, process):
        if not call["status"]:
            return None
        if call["api"] == "RtlDecompressBuffer":
            buf = self.get_argument(call, "UncompressedBuffer")
            if buf.startswith("MZ"):
                self.ret = True
                self.mark_call()    

    def on_complete(self):
        return self.ret
