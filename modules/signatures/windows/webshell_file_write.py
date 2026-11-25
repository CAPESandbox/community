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


class WebshellFileWrite(Signature):
    name = "webshell_file_write"
    description = "Writes a potential webshell or script to disk."
    severity = 1
    categories = ["webshell"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1505"] 

    def run(self):
        file_list = (
            r".*\.ashx$",
            r".*\.aspx$",
            r".*\.jsp$",
            r".*\.jspx$",
            r".*\.php$",
        )

        for ioc in file_list:
            if self.check_write_file(pattern=ioc, regex=True):
                return True

        return False

