# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class AntiAVDetectReg(Signature):
    name = "antiav_detectreg"
    description = "Attempts to identify installed AV products by registry key"
    severity = 3
    categories = ["anti-av"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1063"]  # MITRE v6
    ttps += ["T1012", "T1518"]  # MITRE v6,7,8
    ttps += ["T1518.001"]  # MITRE v7,8
    ttps += ["U1314"]  # Unprotect
    mbcs = ["OB0006", "OB0007"]
    mbcs += ["OC0008", "C0036", "C0036.005"]  # micro-behaviour

    def run(self):
        reg_indicators = [
            r".*\\Software\\(Wow6432Node\\)?Avg$",
            r".*\\Software\\(Wow6432Node\\)?AVAST\\ Software\\.*",
            r".*\\Software\\(Wow6432Node\\)?Avira$",
            r".*\\Software\\(Wow6432Node\\)?Bitdefender$",
            r".*\\Software\\(Wow6432Node\\)?BitDefender\\.*",
            r".*\\Software\\(Wow6432Node\\)?Coranti$",
            r".*\\Software\\(Wow6432Node\\)?Data\\ Fellows\\F-Secure$",
            r".*\\Software\\(Wow6432Node\\)?Doctor\\ Web$",
            r".*\\Software\\(Wow6432Node\\)?ESET$",
            r".*\\Software\\(Wow6432Node\\)?ESET\\.*",
            r".*\\Software\\(Wow6432Node\\)?G\\ Data$",
            r".*\\Software\\(Wow6432Node\\)?Symantec$",
            r".*\\Software\\(Wow6432Node\\)?KasperskyLab\\.*",
            r".*\\Software\\(Wow6432Node\\)?McAfee\\.*",
            r".*\\Software\\(Wow6432Node\\)?McAfee\.com\\.*",
            r".*\\Software\\(Wow6432Node\\)?Microsoft\\Microsoft\\ Antimalware$",
            r".*\\Software\\(Wow6432Node\\)?Network\\ Associates\\TVD$",
            r".*\\Software\\(Wow6432Node\\)?Panda\\ Software$",
            r".*\\Software\\(Wow6432Node\\)?rising$",
            r".*\\Software\\(Wow6432Node\\)?Softed\\ViGUARD$",
            r".*\\Software\\(Wow6432Node\\)?Sophos$",
            r".*\\Software\\(Wow6432Node\\)?Sophos\\.*",
            r".*\\Software\\(Wow6432Node\\)?TrendMicro.*",
            r".*\\Software\\(Wow6432Node\\)?VBA32$",
            r".*\\Software\\(Wow6432Node\\)?Zone\\ Labs\\ZoneAlarm$",
            r".*\\Software\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\App\\ Paths\\mbam.exe$",
            r".*\\SYSTEM\\(CurrentControlSet|ControlSet001)\\services\\Avg.*",
            r".*\\SYSTEM\\(CurrentControlSet|ControlSet001)\\services\\AVP.*",
            r".*\\SYSTEM\\(CurrentControlSet|ControlSet001)\\services\\avast!\\ Antivirus.*",
            r".*\\SYSTEM\\(CurrentControlSet|ControlSet001)\\services\\RsMgrSvc.*",
            r".*\\SYSTEM\\(CurrentControlSet|ControlSet001)\\services\\fshoster.*",
            r".*\\SYSTEM\\(CurrentControlSet|ControlSet001)\\services\\cmdvirth.*",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\AVG_UI$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\AVP$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\mcui_exe$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\mcpltui_exe$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\Bdagent$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\Trend\\ Micro\\ Titanium$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\Trend\\ Micro\\ Client\\ Framework$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\avast$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\MSC$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\BullGuard$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\Sophos\\ AutoUpdate\\ Monitor$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\SpIDerAgent$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\APVXDWIN$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\WRSVC$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\emsisoft\\ anti-malware$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\ISTray$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\G\\ Data\\ AntiVirus\\ Tray.*",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\ZoneAlarm$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\Bkav$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\V3\\ Application$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run\\Baidu\\ Antivirus$",
        ]
        found = False
        for indicator in reg_indicators:
            reg_match = self.check_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                for match in reg_match:
                    self.data.append({"regkey": match})
                found = True
        return found
