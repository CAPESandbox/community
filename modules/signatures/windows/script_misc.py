# Copyright (C) 2024 Kevin Ross

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


class JavaScriptTimer(Signature):
    name = "javascript_timer"
    description = "JavaScript timer detected to delay or measure execution time"
    severity = 1
    confidence = 50
    categories = ["anti-sandbox"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.javascripttimer = [
            "setinterval",
            "settimeout",
        ]

    filter_apinames = set(["JsEval", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            pname = process["process_name"]
            if pname.lower() in ("cscript.exe", "jscript.exe", "mshta.exe", "wscript.exe"):
                javascript = self.get_argument(call, "JavaScript")
                if javascript:
                    for timer in self.javascripttimer:
                        if timer in javascript.lower():
                            self.data.append({"process": pname})
                            self.ret = True
                            if self.pid:
                                self.mark_call()
                            break

        if call["api"] == "COleScript_ParseScriptText":
            pname = process["process_name"]
            if pname.lower() in ("cscript.exe", "jscript.exe", "wscript.exe"):
                javascript = self.get_argument(call, "Script")
                if javascript:
                    for javascripttimer in self.javascripttimer:
                        if javascripttimer in javascript.lower():
                            self.data.append({"process": pname})
                            self.ret = True
                            if self.pid:
                                self.mark_call()
                            break

    def on_complete(self):
        return self.ret
