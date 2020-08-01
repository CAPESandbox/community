# Copyright (C) 2020 bartblaze
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

class StopRansomMutexes(Signature):
    name = "stop_ransom_mutexes"
    description = "Creates a known STOP ransomware variant mutex"
    severity = 3
    categories = ["ransomware"]
    families = ["STOP", "Djvu", "Keypass"]
    authors = ["bartblaze"]
    minimum = "0.5"

    def run(self):
        indicators = [
			"{36A698B9-D67C-4E07-BE82-0EC5B14B4DF5}$",
			"{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}$",
			"{FBB4BCC6-05C7-4ADD-B67B-A98A697323C1}$"
        ]

        for indicator in indicators:
            if self.check_mutex(pattern=indicator, regex=True):
                return True

        return False
