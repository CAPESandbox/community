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

class PrivilegeElevationCheck(Signature):
    name = "privilege_elevation_check"
    description = "Queries process token information to check for Administrator privileges or UAC elevation status"
    severity = 2
    confidence = 80
    categories = ["discovery", "privilege_escalation"]
    authors = ["Kevin Ross", "Gemini"]
    minimum = "1.3"
    evented = True
    ttps = ["T1033", "T1082"] 

    filter_apinames = {
        "NtQueryInformationToken", "GetTokenInformation", "CheckTokenMembership"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    def on_call(self, call, process):
        api = call["api"]
        if api in ("NtQueryInformationToken", "GetTokenInformation"):
            token_class = self.get_argument(call, "TokenInformationClass")
            if token_class:
                try:
                    class_val = int(token_class, 16) if isinstance(token_class, str) and str(token_class).startswith("0x") else int(token_class)
                    # Class 18 = TokenElevationType (Checks if UAC is active/filtering)
                    # Class 20 = TokenElevation (Checks if token is currently elevated)
                    if class_val in (18, 20):
                        self.mark_call()
                        self.ret = True
                except (ValueError, TypeError):
                    pass

        elif api == "CheckTokenMembership":
            sid = self.get_argument(call, "SID") or self.get_argument(call, "SidToCheck")
            if sid and isinstance(sid, str):
                if "S-1-5-32-544" in sid.upper():
                    self.mark_call()
                    self.ret = True

    def on_complete(self):
        return self.ret
