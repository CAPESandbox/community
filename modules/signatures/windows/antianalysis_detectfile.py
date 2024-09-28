# Copyright (C) 2015-2016 KillerInstinct, Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class AntiAnalysisDetectFile(Signature):
    name = "antianalysis_detectfile"
    description = "Attempts to identify installed analysis tools by a known file location"
    severity = 3
    categories = ["anti-analysis", "discovery"]
    authors = ["KillerInstinct", "Brad Spengler", "ditekshen"]
    minimum = "1.2"
    ttps = ["T1063"]  # MITRE v6
    ttps += ["T1083", "T1518"]  # MITRE v6,7,8
    ttps += ["T1518.001"]  # MITRE v7,8
    ttps += ["U1314"]  # Unprotect
    mbcs = ["OB0007", "B0013", "B0013.008", "E1083"]
    mbcs += ["OC0001", "C0051"]  # micro-behaviour

    def run(self):
        file_indicators = [
            r"^[A-Za-z]:\\analysis",
            r"^[A-Za-z]:\\iDEFENSE",
            r"^[A-Za-z]:\\stuff\\odbg110",
            r"^[A-Za-z]:\\gnu\\bin",
            r"^[A-Za-z]:\\Virus\\ Analysis",
            r"^[A-Za-z]:\\popupkiller\.exe$",
            r"^[A-Za-z]:\\tools\\execute\.exe$",
            r"^[A-Za-z]:\\MDS\\WinDump\.exe$",
            r"^[A-Za-z]:\\MDS\\WinDump\.exe$",
            r"^[A-Za-z]:\\guest_tools\\start\.bat$",
            r"^[A-Za-z]:\\tools\\aswsnx",
            r"^[A-Za-z]:\\tools\\decodezeus",
            r"^[A-Za-z]:\\tool\\malmon",
            r"^[A-Za-z]:\\sandcastle\\tools",
            r"^[A-Za-z]:\\tsl\\raptorclient\.exe$",
            r"^[A-Za-z]:\\kit\\procexp\.exe$",
            r"^[A-Za-z]:\\winap\\ckmon\.pyw$",
            r"^[A-Za-z]:\\vmremote\\vmremoteguest\.exe$",
            r"^[A-Za-z]:\\Program\\ Files(\\ \(x86\))?\\Fiddler",
            r"^[A-Za-z]:\\ComboFix",
            r"^[A-Za-z]:\\Program\\ Files(\\ \(x86\))?\\FFDec",
            r"^[A-Za-z]:\\Program\\ Files(\\ \(x86\))?\\Wireshark",
            r"^[A-Za-z]:\\bin\\AHookMonitor\.dll$",
            r"^[A-Za-z]:\\bin\\hookanaapp\.exe$",
            r"^[A-Za-z]:\\bsa\\log_api",
            r"^[A-Za-z]:\\AVCTestSuite\\AVCTestSuite\.exe$",
            r"^[A-Za-z]:\\ipf\\BDCore_U\.dll$",
            r"^[A-Za-z]:\\Kit\\procexp\.exe$",
            r"^[A-Za-z]:\\manual\\grabme\.exe$",
            r"^[A-Za-z]:\\manual\\SilipTCPIP\.exe$",
            r"^[A-Za-z]:\\MWS\\bin\\agent",
            r"^[A-Za-z]:\\original\\AutoRepGui",
            r"^[A-Za-z]:\\totalcmd\\gfiles",
            r"^[A-Za-z]:\\tracer\\FortiTracer\.exe$",
            r"^[A-Za-z]:\\tracer\\mdare32_0\.sys$",
            r"^[A-Za-z]:\\plugins\\(import|process)\\.*\.dll$",
            r"^[A-Za-z]:\\sandbox_svc",
        ]
        ret = False
        for indicator in file_indicators:
            file_match = self.check_file(pattern=indicator, regex=True, all=True)
            if file_match:
                for match in file_match:
                    self.data.append({"file": match})
                ret = True
        return ret
