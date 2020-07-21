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

class EnablesWDigest(Signature):
    name = "enables_wdigest"
    description = "Enables WDigest to store credentials in plaintext"
    severity = 3
    categories = ["persistence", "credential_access", "credential_dumping"]
    authors = ["bartblaze"]
    minimum = "1.3"
    ttp = ["T1112", "T1003"]

    def run(self):
        ret = False
        reg_indicators = [
                "HKEY_LOCAL_MACHINE\\\\System\\\\CurrentControlSet\\\\Control\\\\SecurityProviders\\\\Wdigest\\\\UseLogonCredential$"
        ]

        for indicator in reg_indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"Key" : match})
                ret = True

        return ret
