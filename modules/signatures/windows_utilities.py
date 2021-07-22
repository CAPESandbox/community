# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class UsesWindowsUtilitiesScheduler(Signature):
    name = "uses_windows_utilities_to_create_scheduled_task"
    description = "Uses Windows utilities for basic functionality"
    severity = 2
    confidence = 80
    categories = ["commands", "lateral"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "1.3"
    ttp = ["T1053"]

    evented = True

    def run(self):
        utilities = [
            "at ",
            "at.exe",
            "schtasks",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class UsesWindowsUtilities(Signature):
    name = "uses_windows_utilities"
    description = "Uses Windows utilities for basic functionality"
    severity = 2
    confidence = 80
    categories = ["commands", "lateral"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "1.3"

    evented = True

    def run(self):
        utilities = [
            "attrib",
            "copy",
            "dir ",
            "dir.exe",
            "echo"
            "erase",
            "fsutil",
            "getmac",
            "ipconfig",
            "md ",
            "md.exe",
            "mkdir",
            "move ",
            "move.exe",
            "msdt ",
            "nbtstat",
            "net ",
            "net.exe",
            "netsh",
            "netstat",
            "nslookup",
            "ping",
            "powercfg"
            "qprocess",
            "query ",
            "query.exe",
            "quser",
            "qwinsta",
            "reg ",
            "reg.exe",
            "regsrv32",
            "ren ",
            "ren.exe",
            "rename",
            "route",
            "runas",
            "rwinsta",
            "sc ",
            "sc.exe",
            "set ",
            "set.exe",
            "shutdown",
            "systeminfo",
            "tasklist",
            "telnet",
            "tracert",
            "tree ",
            "tree.exe",
            "type",
            "ver ",
            "ver.exe",
            "whoami",
            "wmic",
            "wusa",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class SuspiciousCommandTools(Signature):
    name = "suspicious_command_tools"
    description = "Uses suspicious command line tools or Windows utilities"
    severity = 3
    confidence = 80
    categories = ["commands", "lateral"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        utilities = [
            "accesschk",
            "accessenum",
            "adexplorer",
            "adinsight",
            "adrestore",
            "autologon",
            "autoruns",
            "bcdedit",
            "bitsadmin",
            "bginfo",
            "cacls",
            "certutil",
            "csvde",
            "del ",
            "del.exe",
            "dsquery",
            "icacls",
            "klist",
            "net ",
            "net.exe",
            "psexec",
            "psfile",
            "psgetsid",
            "psinfo",
            "psping",
            "pskill",
            "pslist",
            "psloggedon",
            "psloglist",
            "pspasswd",
            "psservice",
            "psshutdown",
            "pssuspend",
            "rd ",
            "rd.exe",
            "rexec",
            "sc ",
            "sc.exe",
            "shareenum",
            "shellrunas",
            "takeown ",
            "takeown.exe",
            "taskkill",
            "volumeid",
            "vssadmin",
            "wbadmin",
            "wevtutil",
            "whois",
            "xcacls",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class ScriptToolExecuted(Signature):
    name = "script_tool_executed"
    description = "A scripting utility was executed"
    severity = 2
    confidence = 80
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        utilities = [
            "cscript",
            "powershell",
            "wscript",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class SuspiciousPingUse(Signature):
    name = "suspicious_ping_use"
    description = "A ping command was executed with the -n argument possibly to delay analysis"
    severity = 2
    confidence = 100
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "ping" in lower and ("-n" in lower or "/n" in lower):
                ret = True
                self.data.append({"command" : cmdline})

        return ret

class WMICCommandSuspicious(Signature):
    name = "wmic_command_suspicious"
    description = "Suspicious wmic.exe use was detected"
    severity = 3
    confidence = 80
    categories = ["commands", "wmi"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        self.arguments = [
            "antivirusproduct",
            "baseboard",
            "bios",
            "computersystem",
            "datafile",
            "diskdrive",
            "group",
            "fsdir",
            "logicaldisk",
            "memcache",
            "memorychip",
            "nicconfig",
            "nteventlog",
            "onboarddevice",
            "os get",
            "process",
            "product",
            "qfe",
            "service",
            "startup",
            "sysdriver",
            "useraccount",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "wmic" in lower:
                for argument in self.arguments:
                    if argument in lower:
                        ret = True
                        self.data.append({"command": cmdline})

        return ret

class AltersWindowsUtility(Signature):
    name = "alters_windows_utility"
    description = "Attempts to move, copy or rename a command line or scripting utility likely for evasion"
    severity = 3
    confidence = 100
    categories = ["commands", "stealth", "evasion"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.utilities = [
            "at.exe",
            "bcdedit.exe",
            "bitsadmin.exe",
            "cmd.exe",
            "cscript.exe",
            "dir.exe",
            "nbtstat.exe",
            "net.exe",
            "netsh.exe",
            "nslookup.exe",
            "powershell.exe",
            "regsrv32.exe",
            "sc.exe",
            "schtasks.exe",
            "systeminfo.exe",
            "tasklist.exe",
            "vssadmin.exe",
            "wevutil.exe",
            "wmic.exe",
            "wscript.exe",
            ]

    filter_apinames = set(["CopyFileExA","CopyFileExW","MoveFileWithProgressW","MoveFileWithProgressTransactedW"])

    def on_call(self, call, process):
        self.ret = False
        origfile = self.get_argument(call, "ExistingFileName")
        destfile = self.get_argument(call, "NewFileName")
        for utility in self.utilities:
            lower = origfile.lower()
            if lower.endswith(utility):
                self.ret = True
                self.data.append({"utility" : "source file %s destination file %s" % (origfile,destfile)})

    def on_complete(self):
        return self.ret

class SuspiciousCertutilUse(Signature):
    name = "suspicious_certutil_use"
    description = "Suspicious use of certutil was detected"
    severity = 3
    confidence = 100
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = ["https://www.sentinelone.com/blog/malware-living-off-land-with-certutil/"]
    ttp = ["T1140", "T1130", "T1105"]

    def run(self):

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "certutil" in lower and ("urlcache" in lower or "encode" in lower or "decode" in lower or "addstore" in lower):
                ret = True
                self.data.append({"command" : cmdline})

        return ret

class OverwritesAccessibilityUtility(Signature):
    name = "overwrites_accessibility_utility"
    description = "Overwrites an accessibility feature binary for Windows login bypass, persistence or privilege escalation"
    severity = 3
    confidence = 100
    categories = ["evasion", "privilege_escalation", "persistence"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1015"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.utilities = [
            "atbroker.exe",
            "displayswitch.exe",
            "magnify.exe",
            "narrator.exe",
            "osk.exe",
            "sethc.exe",
            "utilman.exe",
            ]

    filter_apinames = set(["CopyFileExA","CopyFileExW","MoveFileWithProgressW","MoveFileWithProgressTransactedW"])

    def on_call(self, call, process):
        self.ret = False
        origfile = self.get_argument(call, "ExistingFileName")
        destfile = self.get_argument(call, "NewFileName")
        for utility in self.utilities:
            lower = destfile.lower()
            if lower.endswith(utility):
                self.ret = True
                self.data.append({"utility" : "source file %s destination file %s" % (origfile,destfile)})

    def on_complete(self):
        return self.ret

class DotNETCSCBuild(Signature):
    name = "dotnet_csc_build"
    description = "Uses csc.exe C# compiler to build and execute code"
    severity = 3
    confidence = 20
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = ["https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-options/command-line-building-with-csc-exe"]
    ttp = ["T1500"]

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "csc " in lower or "csc.exe" in lower:
                ret = True
                self.data.append({"command" : cmdline})

        return ret

class UsesWindowsUtilitiesCipher(Signature):
    name = "uses_windows_utilities_cipher"
    description = "Uses cipher.exe to wipe the free space, as seen in some ransomware"
    severity = 3
    categories = ["commands", "impact"]
    authors = ["bartblaze"]
    minimum = "1.3"
    ttp = ["T1485"]

    evented = True

    def run(self):
        utilities = [
            "cipher ",
            "cipher.exe",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class UsesWindowsUtilitiesClickOnce(Signature):
    name = "uses_windows_utilities_clickonce"
    description = "Uses ClickOnce Deployment Manifests for download or installation"
    severity = 1
    categories = ["commands", "evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    references = ["http://blog.redxorblue.com/2020/07/one-click-to-compromise-fun-with.html"]
    ttp = ["T1218"]

    evented = True

    def run(self):
        utilities = [
            "dfsvc ",
            "dfsvc.exe",
            "dfshim.dll",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class UsesWindowsUtilitiesMode(Signature):
    name = "uses_windows_utilities_mode"
    description = "Uses MODE to configure a system device or change the code page"
    severity = 1
    categories = ["commands"]
    authors = ["bartblaze"]
    minimum = "1.3"
    references = ["https://www.robvanderwoude.com/mode.php"]

    evented = True

    def run(self):
        utilities = [
            "mode con ",
            "mode lpt ",
            "mode com ",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class UsesWindowsUtilitiesNltest(Signature):
    name = "uses_windows_utilities_nltest"
    description = "Uses nltest to query the Domain Controller"
    severity = 3
    categories = ["discovery"]
    authors = ["bartblaze"]
    minimum = "1.3"
    references = ["https://ss64.com/nt/nltest.html"]
    ttp = ["T1016", "T1482"]
    evented = True

    def run(self):
        utilities = [
            "nltest ",
            "nltest.exe ",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret


class UsesWindowsUtilitiesNTDSutil(Signature):
    name = "uses_windows_utilities_ntdsutil"
    description = "Uses ntdsutil to potentially dump ntds.dit, dump the Active Directory or other actions"
    severity = 3
    categories = ["discovery"]
    authors = ["bartblaze"]
    minimum = "1.3"
    references = ["https://ss64.com/nt/ntdsutil.html"]
    ttp = ["T1003"]
    evented = True

    def run(self):
        utilities = [
            "ntdsutil ",
            "ntdsutil.exe ",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class UsesWindowsUtilitiesCSVDELDFIDE(Signature):
    name = "uses_windows_utilities_csvde_ldifde"
    description = "Attempts to Import or Export Active Directory data to a file"
    severity = 3
    categories = ["discovery"]
    authors = ["bartblaze"]
    minimum = "1.3"
    references = ["https://ss64.com/nt/csvde.html"]
    ttp = ["T1087"]
    evented = True

    def run(self):
        utilities = [
            "CSVDE ",
            "CSVDE.exe ",
            "LDIFDE ",
            "LDIFDE.exe ",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class UsesWindowsUtilitiesDSQuery(Signature):
    name = "uses_windows_utilities_dsquery"
    description = "Searches for an Active Directory object"
    severity = 3
    categories = ["discovery"]
    authors = ["bartblaze"]
    minimum = "1.3"
    references = ["https://ss64.com/nt/dsquery.html"]
    ttp = ["T1069", "T1482", "T1087"]
    evented = True

    def run(self):
        utilities = [
            "DSQuery ",
            "DSQuery.exe ",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class UsesWindowsUtilitiesAppCmd(Signature):
    name = "uses_windows_utilities_appcmd"
    description = "Uses the IIS Command Line Tool, likely for installing a service or loading a file"
    severity = 3
    categories = ["evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    references = ["https://docs.microsoft.com/en-us/iis/get-started/getting-started-with-iis/getting-started-with-appcmdexe"]
    ttp = ["T1202"]
    evented = True

    def run(self):
        utilities = [
            "AppCmd ",
            "AppCmd.exe ",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class SuspiciousMpCmdRunUse(Signature):
    name = "suspicious_mpcmdrun_use"
    description = "Suspicious use of MpCmdRun was detected"
    severity = 3
    categories = ["commands"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttp = ["T1105"]

    def run(self):
        indicators = [
            ".*MpCmdRun(\.exe)?.*-url.*",
        ]

        for indicator in indicators:
            match = self.check_executed_command(pattern=indicator, regex=True)
            if match:
                self.data.append({"command": match})
                return True

        return False

class MultipleExplorerInstances(Signature):
    name = "multiple_explorer_instances"
    description = "Spawns another instance of explorer"
    severity = 2
    categories = ["commands", "evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    references = ["https://twitter.com/CyberRaiju/status/1273597319322058752"]
    evented = True

    def run(self):
        indicators = [
            "explorer.exe /root",
        ]

        for indicator in indicators:
            match = self.check_executed_command(pattern=indicator)
            if match:
                self.data.append({"command": match})
                return True

        return False

class UsesWindowsUtilitiesFinger(Signature):
    name = "uses_windows_utilities_finger"
    description = "Uses the TCPIP Finger Command for downloading files or connecting to a remote server"
    severity = 3
    categories = ["evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    ttp = ["T1202"]
    evented = True

    def run(self):
        utilities = [
            "finger ",
            "finger.exe ",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret
    
class UsesWindowsUtilitiesXcopy(Signature):
    name = "uses_windows_utilities_xcopy"
    description = "Uses XCOPY for copying files"
    severity = 3
    categories = ["evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True

    def run(self):
        utilities = [
            "xcopy ",
            "xcopy.exe ",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class UsesWindowsUtilitiesEsentutl(Signature):
    name = "uses_windows_utilities_esentutl"
    description = "Uses esentutl for copying files"
    severity = 3
    categories = ["evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True

    def run(self):
        utilities = [
            "esentutl ",
            "esentutl.exe ",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret
