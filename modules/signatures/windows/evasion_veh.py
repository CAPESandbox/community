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

class RegistersVectoredExceptionHandler(Signature):
    name = "registers_vectored_exception_handler"
    description = "Registers a vectored exception handler (VEH), possibly to hijack execution flow"
    severity = 2
    confidence = 80
    categories = ["evasion", "execution", "injection"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055", "T1574"]

    filter_apinames = {"RtlAddVectoredExceptionHandler", "AddVectoredExceptionHandler"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    def on_call(self, call, process):
        handler_address = self.get_argument(call, "Handler") or self.get_argument(call, "VectorHandler") 
        if handler_address:
            self.mark_call()
            self.ret = True

    def on_complete(self):
        return self.ret
