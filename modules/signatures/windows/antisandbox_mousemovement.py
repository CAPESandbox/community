# Copyright (C) 2025 Kevin Ross
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


class MouseMovementDetect(Signature):
    name = "mouse_movement_detect"
    description = "Checks for mouse movement"
    severity = 2
    categories = ["anti-sandbox"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1497"]  # MITRE v6,7,8

    filter_apinames = set(["GetCursorPos"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.last_x = 0
        self.last_y = 0
        self.nomovement_count = 0
        self.movement_count = 0

        self.ignoreprocs = [
            "acrobat.exe",
            "acrord32.exe",
            "chrome.exe",
            "excel.exe",
            "hwp.exe",
            "iexplore.exe",
            "firefox.exe",
            "msedge.exe",
            "outlook.exe",
            "powerpnt.exe",
            "winword.exe",
        ]

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname not in self.ignoreprocs:
            xpos = self.get_argument(call, "x")
            ypos = self.get_argument(call, "y")

            if xpos and ypos:
                x = int(xpos, 16)
                y = int(ypos, 16)

                if self.last_x == 0 and self.last_y == 0:
                    self.last_x = x
                    self.last_y = y
                    self.mark_call()
                elif x == self.last_x and y == self.last_y:
                    self.nomovement_count += 1
                    self.mark_call()
                    # self.call_count += 1
                elif x != self.last_x or y != self.last_y:
                    self.movement_count += 1
                    self.last_x = x
                    self.last_y = y
                    self.mark_call()

    def on_complete(self):
        if self.nomovement_count > 15 and self.movement_count < 2:
            self.data.append(
                {
                    "mouse_movement": "Checks for mouse movement (no mouse movement observed in sandbox during many of the samplings)."
                }
            )
            self.ret = True
        elif self.movement_count > 5:
            self.data.append({"mouse_movement": "Checks for mouse movement (mouse movement observed in sandbox during sampling)."})
            self.ret = True

        return self.ret
