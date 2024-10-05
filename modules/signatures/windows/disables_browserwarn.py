# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class DisablesBrowserWarn(Signature):
    name = "disables_browser_warn"
    description = "Attempts to disable browser security warnings"
    severity = 3
    categories = ["generic", "banker", "clickfraud"]
    authors = ["Optiv", "Kevin Ross"]
    minimum = "1.2"
    ttps = ["T1089"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v6,7,8
    ttps += ["T1562", "T1562.001"]  # MITRE v7,8
    mbcs = ["OB0006", "E1112", "F0004"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        indicators = (
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\WarnOnBadCertRecving$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\WarnOnBadCertSending$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\WarnOnHTTPSToHTTPRedirect$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\WarnOnZoneCrossing$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\WarnOnPostRedirect$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Internet\\ Settings\\IEHardenIENoWarn$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Internet\\ Explorer\\Main\\NoProtectedModeBanner$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Internet\\ Explorer\\Main\\IE9RunOncePerInstallCompleted$",
            r".*\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Internet\\ Explorer\\Main\\IE9TourShown$",
        )
        found_match = False
        for indicator in indicators:
            key_match = self.check_write_key(pattern=indicator, regex=True)
            if key_match:
                self.data.append({"regkey": key_match})
                found_match = True
        return found_match
