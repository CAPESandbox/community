# Copyright (C) 2023 bartblaze
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

class api_uuidfromstringa(Signature):
    name = "api_uuidfromstringa"
    description = "Potential malicious use of UuidFromStringA"
    severity = 3
    categories = ["evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    reference = "https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/"

    filter_apinames = set(["LdrGetProcedureAddress"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.dll_loaded = False
        self.ldr = 0

    def on_call(self, call, process):
        if call["api"] == "LdrGetProcedureAddress" and self.get_argument(call, "FunctionName") == "UuidFromStringA":
            self.dll_loaded = True #RPCRT4.dll
            self.ldr = 1
            if self.pid:
                self.mark_call()

    def on_complete(self):
        if self.ldr > 0:
            return True
        else:
            return False
