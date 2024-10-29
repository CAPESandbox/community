from lib.cuckoo.common.abstracts import Signature


class LOLBAS_ExecuteBinaryViaPesterPSModule(Signature):
    name = "Execute_Binary_Via_PesterPSModule"
    description = "Attempts to execute a binary through a legitimate PowerShell Module (Pester)"
    severity = 3
    categories = ["bypass", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = ["https://lolbas-project.github.io/lolbas/Scripts/pester/"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "pester" in lower and not "http" in lower:
                self.data.append({"command": cmdline})
                return True

        return False


class LOLBAS_ExecuteBinaryViaOpenSSH(Signature):
    name = "Execute_Binary_Via_OpenSSH"
    description = "Attempts to execute a binary through a Windows OpenSSH Client"
    severity = 3
    categories = ["bypass", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = ["https://lolbas-project.github.io/lolbas/Binaries/Ssh/"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "ssh" in lower and (
                ("-o" in lower and ("proxycommand=" in lower or "localcommand=" in lower))
                or ("localhost" in lower and ".exe" in lower)
            ):
                self.data.append({"command": cmdline})
                return True

        return False


class LOLBAS_ExecuteBinaryVisualStudioLiveShare(Signature):
    name = "Execute_Binary_Via_VisualStudioLiveShare"
    description = "Attempts to execute a binary through Visual Studio Live Share"
    severity = 3
    categories = ["bypass", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = ["https://twitter.com/bohops/status/1583916360404729857"]
    evented = True

    def run(self):

        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            # False-Positives
            # REF: https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_dll_execution_via_visual_studio_live_share.toml
            if "--pipe" in lower and "visualstudio.com/" in lower:
                return False

            elif "vsls-agent.exe" in lower and "--agentExtensionPath" in lower:
                self.data.append({"command": cmdline})
                return True


class LOLBAS_EvadeExecutionViaDeviceCredentialDeployment(Signature):
    name = "Evade_Execute_Via_DeviceCredentialDeployment"
    description = "Attempts to hide Windows Command Console Window via DeviceCredentialDeployment"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = ["https://lolbas-project.github.io/lolbas/Binaries/DeviceCredentialDeployment/"]
    evented = True

    def run(self):

        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if ("cmd" in lower or "powershell" in lower) and "devicecredentialdeployment" in lower:
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_IndirectCommandExecutionViaConsoleWindowHost(Signature):
    name = "Indirect_Command_Execution_Via_ConsoleWindowHost"
    description = "Abuses conhost.exe to execute an arbitrary executable"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = ["https://lolbas-project.github.io/lolbas/Binaries/Conhost"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if any(process in lower for process in ("cmd /c", "powershell", "script", "mshta", "curl")):
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_EvadeExecutionViaFilterManagerControl(Signature):
    name = "Evade_Execution_Via_Filter_Manager_Control"
    description = "Attempts to unload a security driver via Filter Manager Control"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1562.001"]
    references = ["https://lolbas-project.github.io/lolbas/Binaries/FltMC/"]
    evented = True

    def run(self):
        for cmdline in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            lower = cmdline.lower()
            if "fltmc" in lower and "unload" in lower and any(arg in lower for arg in ("security", "sysmon", "esensor", "Elastic")):
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_EvadeExecutionViaASPNetCompiler(Signature):
    name = "Evade_Execution_Via_ASPNet_Compiler"
    description = "Attempts to execute C# code via ASPNET Compiler"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218.004"]
    references = [
        "https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/",
        "https://ijustwannared.team/2020/08/01/the-curious-case-of-aspnet_compiler-exe/",
    ]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "aspnet_compiler.exe" in lower and "-v" in lower and "-f" in lower and "-u" in lower and not "-d" in lower:
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_EvadeExecutionViaIntelGFXDownloadWrapper(Signature):
    name = "Evade_Execution_Via_Intel_GFXDownloadWrapper"
    description = "Attempts to load a DLL or download remote file using legitimate application shipped by Intel"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = [
        "https://lolbas-project.github.io/lolbas/Binaries/GfxDownloadWrapper/",
        "https://twitter.com/bohops/status/1318767376175976449",
    ]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "gfxdownloadwrapper.exe" in lower and (
                "run" in lower
                and any(arg in lower for arg in ("0", "2"))
                or ("http" in lower and not "https://gameplayapi.intel.com" in lower)
            ):
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_ScriptletProxyExecutionViaPubprn(Signature):
    name = "Scriptlet_Proxy_Execution_Via_Pubprn"
    description = "Attempts to execute malicious processes via trusted PubPrn script"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1059"]
    references = ["https://lolbas-project.github.io/lolbas/Scripts/Pubprn/"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if ("wscript" in lower or "cscript" in lower) and "pubprn" in lower and "script:http" in lower:
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_RegisterDLLViaMSIEXEC(Signature):
    name = "Register_DLL_Via_MSIEXEC"
    description = "Attempts to load suspicious DLL via Msiexec"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1059"]
    references = ["https://lolbas-project.github.io/lolbas/Binaries/Msiexec/"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if (
                "msiexec" in lower
                and any(arg in lower for arg in ("/z", "/y", "-y", "-z"))
                and ".dll" in lower
                and not any(arg in lower for arg in ("\\Program Files\\", "\\Program Files %(x86%)\\"))
            ):
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_RegisterDLLViaOdbcconf(Signature):
    name = "Register_DLL_Via_Odbcconf"
    description = "Attempts to load suspicious DLL via Odbcconf"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = ["https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()

            # Falses:
            # REF: https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_suspicious_imageload_via_odbc_driver_configuration_program.toml
            if ("installmanager.exe" in lower and "\\windows\\syswow64\\odbcconf.rsp" in lower) or (
                "{configsysdsn" in lower and "sql server" in lower
            ):
                return False

            if "odbcconf" in lower and any(arg in lower for arg in ("-a", "-f", "/a", "/f")) and ".dll" in lower:
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_RegisterDLLViaCertOC(Signature):
    name = "Register_DLL_Via_CertOC"
    description = "Attempts to load suspicious DLL via CertOC"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = ["https://lolbas-project.github.io/lolbas/Binaries/Certoc/"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "certoc" in lower and (("-loaddll" in lower and ".dll" in lower) or ("-getcacaps" in lower and "http" in lower)):
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_ExecuteBinaryViaScriptRunner(Signature):
    name = "Execute_Binary_Via_ScriptRunner"
    description = "Attempts to execute malicious binaries via ScriptRunner"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = ["https://lolbas-project.github.io/lolbas/Binaries/Scriptrunner/"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()

            # Exclude conhost.exe (False-postive):
            # REF: https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_system_binary_proxy_execution_via_scriptrunner.toml
            if "scriptrunner" in lower and "-appvscript" in lower and not ("conhost" in lower and "0xffffffff" in lower):
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_ExecuteMsiexecViaExplorer(Signature):
    name = "Execute_Msiexec_Via_Explorer"
    description = "Attempts to execute malicious Msiexec installer via Explorer in quite mode"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_windows_installer_execution_via_explorer.toml"
    ]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if (
                "explorer" in lower
                and "msiexec" in lower
                and any(arg in lower for arg in ["/i", "-i"])
                and any(arg in lower for arg in ["/qn", "-qn", "-q", "/q", "/quiet"])
            ):
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_PerformMaliciousActivitiesViaHeadlessBrowser(Signature):
    name = "Perform_Malicious_Activities_Via_Headless_Browser"
    description = "Attempts to execute/download malicious files via web browsers"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1105"]
    references = ["https://lolbas-project.github.io/lolbas/Binaries/Msedge/"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()

            # I have tried it on other browsers
            if any(
                process in lower
                for process in ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "dragon.exe", "vivaldi.exe")
            ) and (
                any(spawn in lower for spawn in ("cmd", "powershell", "wscript", "cscript"))
                or ("headless" in lower and "http" in lower and not "http://localhost/allure#graph" in lower)
            ):
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_ExecuteBinaryViaRunExeHelperUtility(Signature):
    name = "execute_binary_via_run_exe_helper_utility"
    description = "Attempts to execute malicious binaries via RunExeHelper utility"
    severity = 3
    categories = ["bypass", "stealth", "execution"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1218"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_binary_proxy_execution_via_runexehelper.toml"
    ]

    filter_apinames = set(["CreateProcessInternalW"])

    def on_call(self, call, process):
        # Checking parent process for false positives.
        if (
            process["process_name"].lower()
            in [
                "conhost.exe",
                "powercfg.exe",
                "wevtutil.exe",
                "wscollect.exe",
                "tpmtool.exe",
                "mdmdiagnosticstool.exe",
                "dsregcmd.exe",
                "stordiag.exe",
                "dxdiag.exe",
                "logman.exe",
                "licensingdiag.exe",
            ]
            and call["api"] == "CreateProcessInternalW"
        ):
            cmdline = self.get_argument(call, "CommandLine")
            lower = cmdline.lower()
            if "runexehelper.exe" in lower:
                return False

    def on_complete(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "runexehelper.exe" in lower and lower.endswith(".exe"):
                self.data.append({"command": cmdline})
                return True
        return False


class LOLBAS_ExecuteBinaryViaTTDinject(Signature):
    name = "execute_binary_via_ttdinject"
    description = "Attempts to execute a binary via the Time Traver Debugging Application Injector utility"
    severity = 3
    categories = ["bypass", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = ["https://lolbas-project.github.io/lolbas/Binaries/Ttdinject/"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "ttdinject.exe" in lower and "/launch" in lower and not "\\ttdinject.exe" in lower:
                self.data.append({"command": cmdline})
                return True

        return False


class LOLBAS_ExecuteBinaryViaAppVLP(Signature):
    name = "execute_binary_via_appvlp"
    description = "Attempts to execute a binary via the Application Virtualization Utility"
    severity = 3
    categories = ["bypass", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = [
        "https://lolbas-project.github.io/lolbas/OtherMSBinaries/Appvlp/",
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_binary_proxy_execution_via_appvlp.toml",
    ]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "appvlp.exe" in lower and not (
                "\\program files\\" in lower or "\\program files (x86)\\" in lower or "rundll32.exe" in lower
            ):
                self.data.append({"command": cmdline})
                return True

        return False


class LOLBAS_ExecuteBinaryViaInternetExplorerExporter(Signature):
    name = "execute_binary_via_internet_explorer_exporter"
    description = "Attempts to load malicious DLLs via the Internet Explorer Exporter"
    severity = 3
    categories = ["bypass", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = ["https://www.hexacorn.com/blog/2018/04/24/extexport-yet-another-lolbin/"]
    evented = True

    filter_apinames = set(["NtCreateFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False
        self.blacklistedNames = ["mozcrt19.dll", "mozsqlite3.dll", "sqlite3.dll"]
        self.whitelistedDirectories = [
            "\\program files (x86)\\",
            "\\program files\\",
            "\\windows\\system32\\",
            "\\windows\\syswow64\\",
        ]

    def on_call(self, call, _):
        if call["api"] == "NtCreateFile":
            filename = self.get_argument(call, "FileName").lower()
            handle = int(self.get_argument(call, "FileHandle"), 16)
            if handle:
                if any(dllName in filename for dllName in self.blacklistedNames) and not any(
                    Dir in filename for Dir in self.whitelistedDirectories
                ):
                    self.detected = True

    def on_complete(self):
        if self.detected:
            cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
            for cmdline in cmdlines:
                lower = cmdline.lower()
                if "extexport.exe" in lower:
                    self.data.append({"command": cmdline})
                    return True
        return False


class LOLBAS_ExecuteSuspiciousPowerShellViaSQLPS(Signature):
    name = "execute_suspicious_powershell_via_sqlps"
    description = "Attempts to execute a suspicious PowerShell commands via the Microsoft SQL Powershell Helper Tools"
    severity = 3
    categories = ["bypass", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1059", "T1218"]
    references = ["https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqltoolsps/"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if any(process in lower for process in ("sqltoolsps.exe", "sqlps.exe")) and any(
                arg in lower
                for arg in (
                    "-e",
                    "-enc",
                    "-ep",
                    "-encoded",
                    ";iex",
                    "start-process",
                    "webclient",
                    "downloadfile",
                    "downloadstring",
                    "bitstransfer",
                    "reflection.assembly",
                )
            ):
                self.data.append({"command": cmdline})
                return True

        return False


class LOLBAS_ExecuteSuspiciousPowerShellViaRunscripthelper(Signature):
    name = "execute_suspicious_powershell_via_runscripthelper"
    description = "Attempts to execute a suspicious PowerShell commands via the RunScriptHelper utility"
    severity = 3
    categories = ["bypass", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1059", "T1218"]
    references = ["https://lolbas-project.github.io/lolbas/Binaries/Runscripthelper/"]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            argumentCount = lower.split()
            if "runscripthelper.exe" in lower and "surfacecheck" and (len(argumentCount) - 1) > 3:
                self.data.append({"command": cmdline})
                return True

        return False
