# Copyright (C) 2021 ditekshen
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

class QuilMinerNetworkBehavior(Signature):
    name = "quilclipper_behavior"
    description = "QuilMiner network artifacts detected"
    severity = 3
    categories = ["miner"]
    families = ["QuilMiner"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False

    filter_apinames = set(["InternetOpenA", "InternetOpenW"])

    def on_call(self, call, process):
        agent = self.get_argument(call, "Agent")
        if agent:
            if "quilminer" in agent.lower():
                self.match = True

    def on_complete(self):
        return self.match
