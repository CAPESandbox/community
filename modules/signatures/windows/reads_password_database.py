# Copyright (C) 2025 bartblaze
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class ReadsPasswordDatabase(Signature):
    name = "reads_password_database"
    description = "A file with a password database extension was accessed"
    severity = 2
    categories = ["credential_access"]
    authors = ["bartblaze"]
    minimum = "1.2"
    ttps = ["T1555", "T1555.005"]
    evented = True

    def run(self):
        exts = [
            ".kdb",           # KeePass legacy
            ".kdbx",          # KeePass
            ".opvault",       # 1Password
            ".1pif",          # 1Password
            ".psafe3",        # Password Safe
            ".walletx",       # Enpass
            ".enpassbackup",  # Enpass backup
        ]

        ext_pattern = "|".join(re.escape(e.lstrip(".")) for e in exts)
        pattern = r"(?i).*\.(%s)$" % ext_pattern

        matches = self.check_file(pattern=pattern, regex=True, all=True)
        if matches:
            self.data.extend([{"file": m} for m in matches])

        return bool(matches)
