# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class AntiAVDetectFile(Signature):
    name = "antiav_detectfile"
    description = "Attempts to identify installed AV products by installation directory"
    severity = 3
    categories = ["anti-av"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1063"]  # MITRE v6
    ttps += ["T1083", "T1518"]  # MITRE v6,7,8
    ttps += ["T1518.001"]  # MITRE v7,8
    ttps += ["U1314"]  # Unprotect
    mbcs = ["OB0007", "E1083"]
    mbcs += ["OC0001", "C0051"]  # MBC micro-behaviour

    def run(self):
        file_indicators = (
            r".*\\AVAST\ Software",
            r".*\\Avira\ GmbH",
            r".*\\Avira",
            r".*\\Kaspersky\ Lab",
            r".*\\Kaspersky\ Lab\\ Setup\\ Files",
            r".*\\DrWeb",
            r".*\\Norton\ AntiVirus",
            r".*\\Norton\ (Security with Backup|Internet Security)\\",
            r".*\\ESET",
            r".*\\Agnitum",
            r".*\\Panda\ Security",
            r".*\\McAfee",
            r".*\\McAfee\.com",
            r".*\\Trend\ Micro",
            r".*\\BitDefender",
            r".*\\ArcaBit",
            r".*\\Online\ Solutions",
            r".*\\AnVir\ Task\ Manager",
            r".*\\Alwil\ Software",
            r".*\\Symantec$",
            r".*\\AVG",
            r".*\\Xore",
            r".*\\Symantec\ Shared",
            r".*\\a-squared\ Anti-Malware",
            r".*\\a-squared\ HiJackFree",
            r".*\\avg8",
            r".*\\Doctor\ Web",
            r".*\\f-secure",
            r".*\\F-Secure\\ Internet\ Security",
            r".*\\G\ DATA",
            r".*\\P\ Tools",
            r".*\\P\ Tools\ Internet\ Security",
            r".*\\K7\ Computing",
            r".*\\Vba32",
            r".*\\Sunbelt\ Software",
            r".*\\FRISK\ Software",
            r".*\\Security\ Task\ Manager",
            r".*\\Zillya\ Antivirus",
            r".*\\Spyware\ Terminator",
            r".*\\Lavasoft",
            r".*\\BlockPost",
            r".*\\DefenseWall\ HIPS",
            r".*\\DefenseWall",
            r".*\\Microsoft\ Antimalware",
            r".*\\Microsoft\ Security\ Essentials",
            r".*\\Sandboxie",
            r".*\\Positive\ Technologies",
            r".*\\UAenter",
            r".*\\Malwarebytes",
            r".*\\Malwarebytes'\ Anti-Malware",
            r".*\\Microsoft\ Security\ Client",
            r".*\\System32\\drivers\\kl1\\.sys$",
            r".*\\System32\\drivers\\(tm((actmon|comm)\\.|e(vtmgr\\.|ext\\.)|(nciesc|tdi)\\.)|TMEBC32\\.)sys$",
        )
        found = False
        for indicator in file_indicators:
            file_match = self.check_file(pattern=indicator, regex=True, all=True)
            if file_match:
                for match in file_match:
                    self.data.append({"file": match})
                found = True
        return found
