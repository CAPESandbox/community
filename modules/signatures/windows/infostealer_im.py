# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class IMStealer(Signature):
    name = "infostealer_im"
    description = "Harvests information related to installed instant messenger clients"
    severity = 3
    categories = ["infostealer"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttps = ["T1081"]  # MITRE v6
    ttps += ["T1003", "T1005"]  # MITRE v6,7,8
    ttps += ["T1552", "T1552.001"]  # MITRE v7,8
    mbcs = ["OB0003", "OB0005"]

    def run(self):
        file_indicators = (
            r".*\\AIM\\aimx\.bin$",
            r".*\\Digsby\\loginfo\.yaml$",
            r".*\\Digsby\\Digsby\.dat$",
            r".*\\Meebo\\MeeboAccounts\.txt$",
            r".*\\Miranda\\.*\.dat$",
            r".*\\MySpace\\IM\\users\.txt$",
            r".*\\\.purple\\Accounts\.xml$",
            r".*\\Application\\ Data\\Miranda\\.*",
            r".*\\AppData\\Roaming\\Miranda\\.*",
            r".*\\Skype\\.*\\config\.xml$",
            r".*\\Tencent\\ Files\\.*\\QQ\\Registry\.db$",
            r".*\\Trillian\\users\\global\\accounts\.ini$",
            r".*\\Xfire\\XfireUser\.ini$",
        )
        registry_indicators = (
            r".*\\Software\\(Wow6432Node\\)?America\\ Online\\AIM6\\Passwords.*",
            r".*\\Software\\(Wow6432Node\\)?AIM\\AIMPRO\\.*",
            r".*\\Software\\(Wow6432Node\\)?Beyluxe\\ Messenger\\.*",
            r".*\\Software\\(Wow6432Node\\)?BigAntSoft\\BigAntMessenger\\.*",
            r".*\\Software\\(Wow6432Node\\)?Camfrog\\Client\\.*",
            r".*\\Software\\(Wow6432Node\\)?Google\\Google\\ Talk\\Accounts.*",
            r".*\\Software\\(Wow6432Node\\)?IMVU\\.*",
            r".*\\Software\\(Wow6432Node\\)?Nimbuzz\\PCClient\\Application\\.*",
            r".*\\Software\\(Wow6432Node\\)?Paltalk.*",
            r".*\\Software\\(Wow6432Node\\)?Yahoo\\Pager\\.*",
        )
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
