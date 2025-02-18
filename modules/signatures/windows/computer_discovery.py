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


class QueriesComputerName(Signature):
    name = "queries_computer_name"
    description = "Queries computer hostname"
    severity = 1
    categories = ["system_discovery"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1614"]  # MITRE v6,7,8

    filter_apinames = set(["GetComputerNameA", "GetComputerNameW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    def on_call(self, call, process):
        self.mark_call()
        self.ret = True

    def on_complete(self):
        return self.ret


class QueriesUserName(Signature):
    name = "queries_user_name"
    description = "Queries the username"
    severity = 1
    categories = ["system_discovery"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1614"]  # MITRE v6,7,8

    filter_apinames = set(["GetUserNameA", "GetUserNameW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    def on_call(self, call, process):
        self.mark_call()
        self.ret = True

    def on_complete(self):
        return self.ret
