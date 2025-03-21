# Copyright (C) 2012-2014 Claudio "nex" Guarnieri (@botherder), Optiv Inc. (brad.spengler@optiv.com)
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


class FTPStealer(Signature):
    name = "infostealer_ftp"
    description = "Harvests credentials from local FTP client softwares"
    severity = 3
    categories = ["infostealer"]
    authors = ["nex", "Optiv"]
    minimum = "1.2"
    ttps = ["T1081"]  # MITRE v6
    ttps += ["T1003", "T1005"]  # MITRE v6,7,8
    ttps += ["T1552", "T1552.001"]  # MITRE v7,8
    mbcs = ["OB0003", "OB0005"]

    def run(self):
        file_indicators = [
            r".*\\CuteFTP\\sm\.dat$",
            r".*\\FlashFXP\\.*\\Sites\.dat$",
            r".*\\FlashFXP\\.*\\Quick\.dat$",
            r".*\\FileZilla\\sitemanager\.xml$",
            r".*\\FileZilla\\recentservers\.xml$",
            r".*\\FTPRush\\RushSite\.xml$",
            r".*\\VanDyke\\Config\\Sessions\\.*",
            r".*\\Far\ Manager\\.*",
            r".*\\FTP\ Explorer\\.*",
            r".*\\FTP\ Commander.*",
            r".*\\SmartFTP\\.*",
            r".*\\TurboFTP\\.*",
            r".*\\FTPRush\\.*",
            r".*\\LeapFTP\\.*",
            r".*\\FTPGetter\\.*",
            r".*\\ALFTP\\.*",
            r".*\\Ipswitch\\WS_FTP\\.*",
            r".*\\cftp\\ftplist.txt$",
        ]
        registry_indicators = [
            r".*\\Software\\(Wow6432Node\\)?Far.*\\Hosts$",
            r".*\\Software\\(Wow6432Node\\)?Far.*\\FTPHost$",
            r".*\\Software\\(Wow6432Node\\)?GlobalSCAPE\\CuteFTP.*",
            r".*\\Software\\(Wow6432Node\\)?Ghisler\\Windows Commander.*",
            r".*\\Software\\(Wow6432Node\\)?Ghisler\\Total Commander.*",
            r".*\\Software\\(Wow6432Node\\)?BPFTP\\.*",
            r".*\\Software\\(Wow6432Node\\)?FileZilla.*",
            r".*\\Software\\(Wow6432Node\\)?TurboFTP.*",
            r".*\\Software\\(Wow6432Node\\)?Sota\\FFFTP.*",
            r".*\\Software\\(Wow6432Node\\)?FTPWare\\CoreFTP\\.*",
            r".*\\Software\\(Wow6432Node\\)?FTP\\ Explorer\\.*",
            r".*\\Software\\(Wow6432Node\\)?FTPClient\\.*",
            r".*\\Software\\(Wow6432Node\\)?LinasFTP\\.*",
            r".*\\Software\\(Wow6432Node\\)?Robo-FTP.*",
            r".*\\Software\\(Wow6432Node\\)?MAS-Soft\\FTPInfo\\.*",
            r".*\\Software\\(Wow6432Node\\)?SoftX\.org\\FTPClient\\.*",
            r".*\\Software\\(Wow6432Node\\)?NCH\\ Software\\CoreFTP\\.*",
            r".*\\Software\\(Wow6432Node\\)?BulletProof Software\\BulletProof FTP Client.*",
        ]
        found_stealer = False
        for indicator in file_indicators:
            file_match = self.check_file(pattern=indicator, regex=True, all=True)
            if file_match:
                for match in file_match:
                    self.data.append({"file": match})
                found_stealer = True
        for indicator in registry_indicators:
            key_match = self.check_key(pattern=indicator, regex=True, all=True)
            if key_match:
                for match in key_match:
                    self.data.append({"regkey": match})
                found_stealer = True
        return found_stealer
