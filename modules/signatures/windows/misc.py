from lib.cuckoo.common.abstracts import Signature


class SuspiciousExecutionViaMicrosoftExchangeTransportAgent(Signature):
    name = "Suspicious_Execution_Via_MicrosoftExchangeTransportAgent"
    description = (
        "Attempts to execute a suspicious commands via MicrosoftExchangeTransportAgent for persistence or or malicious activities"
    )
    severity = 3
    categories = ["evasion", "execution", "persistence"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1505.002"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/persistence_suspicious_execution_via_microsoft_exchange_transport_agent.toml"
    ]

    filter_apinames = set(["CreateProcessInternalW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, process):
        if (
            process["process_name"].lower() in ("msexchangetransport.exe", "edgetransport.exe")
            and call["api"] == "CreateProcessInternalW"
        ):
            cmdline = self.get_argument(call, "CommandLine")
            lower = cmdline.lower()
            if any(
                process in lower
                for process in (
                    "wscript.exe",
                    "cscript.exe",
                    "mshta.exe",
                    "certutil.exe",
                    "certreq.exe",
                    "bitsadmin.exe",
                    "curl.exe",
                    "reg.exe",
                    "net.exe",
                )
            ):
                self.detected = True
                return

    def on_complete(self):
        if self.detected:
            return True
        return False


class SuspiciousScheduledTaskCreationviaMasqueradedXMLFile(Signature):
    name = "Suspicious_Scheduled_Task_Creation_Via_Masqueraded_XML_File"
    description = "Attempts to schedule tasks using an XML files that doesn't have .xml extensions"
    severity = 3
    categories = ["evasion", "execution", "persistence"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1053.005"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/persistence_suspicious_scheduled_task_creation_via_masqueraded_xml_file.toml"
    ]

    filter_apinames = set(["CreateProcessInternalW"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()

        # Checking parent process for false positives.
        if (
            pname
            in (
                "setup_msi.exe",
                "setupactions.exe",
                "admsetupactions.exe",
                "antimalware.exe",
                "pcdrcui.exe",
                "setupactions.exe",
                "setupactions.exe",
                "wincompose.exe",
            )
            and call["api"] == "CreateProcessInternalW"
        ):
            cmdline = self.get_argument(call, "CommandLine")
            lower = cmdline.lower()
            if "schtasks.exe" in lower:
                return False

        if pname == "rundll32.exe" and call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine")
            lower = cmdline.lower()
            if "tmp,zzzzinvokemanagedcustomactionoutofproc" in lower:
                return False

    def on_complete(self):
        for cmdline in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            lower = cmdline.lower()
            if (
                "schtasks.exe" in lower
                and any(arg in lower for arg in ("/create", "-create"))
                and any(arg in lower for arg in ("/xml", "-xml"))
                and not ".xml" in lower
            ):
                return True
        return False


class PotentialProtocolTunnelingViaLegitUtilities(Signature):
    name = "potential_protocol_tunneling_via_legit_utilities"
    description = "Attempts to use legit utilities to potentially tunnel network traffic"
    severity = 3
    categories = ["network"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1572"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/command_and_control_potential_protocol_tunneling_via_legit_utilities.toml"
    ]
    evented = True

    def run(self):
        for cmdline in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            lower = cmdline.lower()
            if (
                "3389" in lower
                and any(arg in lower for arg in ("-L", "-P", "-R", "-pw", "-ssh"))
                or "ssh.exe" in lower
                and any(arg in lower for arg in ("127.0.0", "localhost"))
                or "ngrok" in lower
                and any(arg in lower for arg in ("http", "tcp", "tunnel", "tls", "start", "3389"))
            ):
                return True

        return False


class PotentialProtocolTunnelingViaQEMU(Signature):
    name = "potential_protocol_tunneling_via_qemu"
    description = "Attempts to use legit utilities to potentially tunnel network traffic via QEMU emulator"
    severity = 3
    categories = ["network"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1572"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/command_and_control_potential_traffic_tunneling_with_qemu.toml"
    ]
    evented = True

    def run(self):
        for cmdline in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            lower = cmdline.lower()
            if "qemu" in lower and "netdev" in lower and "nographic" in lower and "restrict=off" in lower:
                return True

        return False


class PotentialLocationDiscoveryViaUnusualProcess(Signature):
    name = "potential_location_discovery_via_unusual_process"
    description = "Attempts to perform browser or internet location discovery from an unusual process"
    severity = 3
    categories = ["infostealer"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1016", "T1016.001"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/discovery_potential_hawkeyes_stealer_infection.toml"
    ]
    evented = True

    filter_apinames = set(["CreateProcessInternalW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, process):
        pnameFullPath = process["module_path"].lower()
        if (not "\\endpoint protection sdk\\endpointprotection.exe" in pnameFullPath) or (
            not "\\aemagent\\rmm.advancedthreatdetection\\dattoav\\endpoint protection sdk\\endpointprotection.exe" in pnameFullPath
        ):
            if call["api"] == "CreateProcessInternalW":
                cmdline = self.get_argument(call, "CommandLine")
                lower = cmdline.lower()
                if (
                    any(process in lower for process in ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "dragon.exe"))
                    and "--dump-dom" in lower
                    and "http" in lower
                ):
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class ExecutionFromSelfExtractingArchive(Signature):
    name = "execution_from_self_extracting_archive"
    description = "Attempts to execute a file from a password protected self-extracting archive"
    severity = 3
    categories = ["bypass"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1204"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/execution_execution_from_a_password_protected_self_extracting_archive.toml"
    ]
    evented = True

    filter_apinames = set(["NtCreateFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, _):
        if call["api"] == "NtCreateFile":
            fileName = self.get_argument(call, "FileName")
            handle = int(self.get_argument(call, "FileHandle"), 16)
            if handle and "_sfx_access_check" in fileName:
                self.detected = True

    def on_complete(self):
        if self.detected:
            cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
            for cmdline in cmdlines:
                lower = cmdline.lower()
                if "sfx.exe" in lower and "-p" in lower and "-d" in lower:
                    self.data.append({"command": cmdline})
                    return True
        return False


class SuspiciousJavaExecutionViaWinScripts(Signature):
    name = "suspicious_java_execution_via_win_scripts"
    description = "Attempts to execute jar files via Win Scripts to bypass whitelisting"
    severity = 3
    categories = ["bypass"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1059"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/execution_suspicious_java_execution_via_a_windows_script.toml"
    ]
    evented = True

    filter_apinames = set(["CreateProcessInternalW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, process):
        if process["process_name"].lower() in ("wscript.exe", "cscript.exe") and call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine")
            lower = cmdline.lower()
            if (
                "java.exe" in lower
                and "-jar" in lower
                and any(arg in lower for arg in ("\\appdata\\", "\\public\\", "\\programdata\\"))
            ):
                self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class AMSIBypassViaCOMRegistry(Signature):
    name = "amsi_bypass_via_com_registry"
    description = "Attempts to disable the Microsoft Antimalware Scan Interface via registry"
    severity = 3
    categories = ["evasion"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1562"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_amsi_bypass_via_com_registry_modification.toml",
        "https://blog.sonicwall.com/en-us/2023/03/asyncrat-variant-includes-cryptostealer-capabilites/",
    ]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, _):
        if call["api"] in ("RegSetValueExA", "RegSetValueExW"):
            regKeyPath = self.get_argument(call, "FullName").lower()
            buf = self.get_argument(call, "Buffer")
            if "{fdb00e52-a214-4aa1-8fba-4357bb0072ec}\\inprocserver" in regKeyPath and buf != "amsi.dll":
                self.data.append({"Value": buf})
                self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class LoadDLLViaControlPanel(Signature):
    name = "load_dll_via_control_panel"
    description = "Attempt to load malicious DLL when Control Panel is executed"
    severity = 3
    categories = ["evasion", "bypass"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1218"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_dll_control_panel_items_registry_modification.toml"
    ]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False
        self.falseProcess = ("svchost.exe", "drvinst.exe", "msiexec.exe")

    def on_call(self, call, process):
        if not (
            process["process_name"].lower in self.falseProcess
            or "windows\\system32\\driverstore\\filerepository" in process["module_path"].lower()
        ):

            if call["api"] in ("RegSetValueExA", "RegSetValueExW"):
                regKeyPath = self.get_argument(call, "FullName").lower()
                buf = self.get_argument(call, "Buffer")
                type = self.get_argument(call, "Type")

                if (
                    any(
                        key in regKeyPath
                        for key in (
                            "software\\microsoft\\windows\\currentversion\\control panel\\cpls",
                            "software\\microsoft\\windows\\currentversion\\control panel\\cpls\\",
                        )
                    )
                    and not buf != ""
                    and not type != "4"
                ):
                    self.data.append({"regkey": regKeyPath})
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class DLLHijackingViaWaaSMedicSvcCOMTypeLib(Signature):
    name = "dll_hijacking_via_waas_medic_svc_com_typelib"
    description = "Attempts to load malicious DLL via WaaSMedicSvc COM TypeLib"
    severity = 3
    categories = ["evasion", "persistence"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1546"]
    references = [
        "https://blog.scrt.ch/2023/03/17/bypassing-ppl-in-userland-again/",
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_waasmedicsvc_com_type_lib_hijack.toml",
    ]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, process):
        if not "\\Windows\\System32\\svchost.exe" in process["module_path"]:
            if call["api"] in ("RegSetValueExA", "RegSetValueExW"):
                regKeyPath = self.get_argument(call, "FullName").lower()
                buf = self.get_argument(call, "Buffer")
                if (
                    "\\software\\classes\\typelib\\{3ff1aab8-f3d8-11d4-825d-00104b3646c0}\\" in regKeyPath and buf.endswith(".dll")
                ) and not buf.endswith("WaaSMedicPS.dll"):
                    self.data.append({"Value": buf})
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class MSOfficeCMDRCE(Signature):
    name = "ms_office_cmd_rce"
    description = "Attempts to execute arbitrary code via Microsoft OfficeCmd URL Handler"
    severity = 3
    categories = ["evasion", "execution"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    ttps = ["T1189"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/initial_access_suspicious_execution_via_microsoft_officecmd_url_handler.toml"
    ]

    def run(self):
        for cmdline in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            lower = cmdline.lower()
            if "localbridge" in lower and any(
                arg in lower for arg in ("ms-officecmd", "launchofficeappforresult", "--gpu-launcher")
            ):
                self.data.append({"command": cmdline})
                return True
        return False


class StoreExecutableRegistry(Signature):
    name = "store_executable_registry"
    description = "Stores an executable bytes in Registry for possible future loading"
    severity = 2
    categories = ["evasion", "persistence"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1027"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_potential_executable_stored_in_the_registry.toml"
    ]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, process):
        if call["api"] in ("RegSetValueExA", "RegSetValueExW", "NtSetValueKey"):
            valueName = self.get_argument(call, "ValueName")
            bufLen = self.get_argument(call, "BufferLength")

            if not (
                "\\Program Files (x86)\\Schneider Electric\\Software Update\\SoftwareUpdate.exe" in process["module_path"]
                and valueName == "FusTMP"
            ):
                buf = self.get_argument(call, "Buffer")
                if buf and buf.startswith("MZ\\x90\\x00") and int(bufLen) >= 100:
                    if self.pid:
                        self.mark_call()
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class DLLHijackingViaMicrosoftExchange(Signature):
    name = "dll_hijacking_via_microsoft_exchange"
    description = "Attempts to hijack a DLL via Microsoft Exchange"
    severity = 2
    categories = ["evasion"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1574"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_privilege_escalation_via_microsoft_exchange_dll_hijacking.toml"
    ]

    filter_apinames = set(["NtCreateFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, process):
        if process["process_name"].lower() == "w3wp.exe":
            if call["api"] == "NtCreateFile":
                filename = self.get_argument(call, "FileName").lower()
                if filename.endswith(".dll") and "d:\\managedtools\\cmdlets" in filename:
                    if self.pid:
                        self.mark_call()
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class IPAddressDiscoveryViaTrustedProgram(Signature):
    name = "ip_address_discovery_via_trusted_program"
    description = "Attempts to perform IP discovery via a trusted Program"
    severity = 2
    categories = ["discovery", "network"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1016"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/discovery_external_ip_address_discovery_via_a_trusted_program.toml"
    ]

    filter_apinames = set(["InternetOpenUrlA"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False
        self.domains = (
            "ip-api.com",
            "checkip.dyndns.org",
            "api.ipify.org",
            "api.ipify.com",
            "whatismyip.akamai.com",
            "bot.whatismyipaddress.com",
            "ifcfg.me",
            "ident.me",
            "ipof.in",
            "ip.tyk.nu",
            "icanhazip.com",
            "curlmyip.com",
            "wgetip.com",
            "eth0.me",
            "ipecho.net",
            "ip.appspot.com",
            "api.myip.com",
            "geoiptool.com",
            "api.2ip.ua",
            "api.ip.sb",
            "ipinfo.io",
            "checkip.amazonaws.com",
            "wtfismyip.com",
            "iplogger.*",
            "freegeoip.net",
            "freegeoip.app",
            "ipinfo.io",
            "geoplugin.net",
            "myip.dnsomatic.com",
            "www.geoplugin.net",
            "api64.ipify.org",
            "ip4.seeip.org",
            "*.geojs.io",
            "*portmap.io",
            "api.2ip.ua",
            "api.db-ip.com",
            "geolocation-db.com",
            "httpbin.org",
            "myip.opendns.com",
        )
        self.trustedNames = (
            "wscript.exe",
            "cscript.exe",
            "regsvr32.exe",
            "mshta.exe",
            "rundll32.exe",
            "vbc.exe",
            "powershell.exe",
            "pwsh.exe",
            "msbuild.exe",
            "wmic.exe",
            "cmstp.exe",
            "regasm.exe",
            "installutil.exe",
            "regsvcs.exe",
            "msxsl.exe",
            "xwizard.exe",
            "csc.exe",
            "curl.exe",
            "java.exe",
            "javaw.exe",
        )

    def on_call(self, call, process):
        if any(proc in process["process_name"].lower() for proc in self.trustedNames):
            if call["api"] == "InternetOpenUrlA":
                url = self.get_argument(call, "URL")
                if url:
                    for domain in self.domains:
                        if domain in url:
                            self.detected = True
                            if self.pid:
                                self.mark_call()

    def on_complete(self):
        if self.detected:
            return True
        return False


class MountCopyToWebDavShare(Signature):
    name = "mount_copy_to_webdav_share"
    description = "Attempts to Mount a Remote WebDav Share"
    severity = 2
    categories = ["network", "discovery"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1204.002"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/execution_attempt_to_mount_a_remote_webdav_share.toml"
    ]
    evented = True

    def run(self):
        for cmdline in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            lower = cmdline.lower()
            if ("rundll32.exe" in lower and "\\program files\\microsoft office\\root\\office16\\mlcfg32.cpl" in lower) or (
                any(
                    proc in lower
                    for proc in (
                        "c:\\program files\\microsoft office\\root\\office16\\winproj.exe",
                        "d:\\sf-deploy\\console\\console.exe",
                        "c:\\program files\\windowsapps\\mycaseinc.mycasefilesync_*\\app\\mycase desktop.exe",
                    )
                )
            ):
                return False

            if (
                ("explorer.exe" in lower and "\\" in lower and "@" in lower)
                or ("net.exe" in lower and "use" in lower)
                or (any(arg in lower for arg in ("http", "webdav")) and "/user" in lower and "//localhost" not in lower)
                or (
                    any(proc in lower for proc in ("expand.exe", "xcopy.exe", "cmd.exe"))
                    and any(arg in lower for arg in ("\\\\webdav", "davwwwroot"))
                )
            ):
                return True

        return False


class ExecuteFileDownloadedViaOpenSSH(Signature):
    name = "execute_file_downloaded_via_openssh"
    description = "Attempts to execute suspicious file downloaded via OpenSSH"
    severity = 2
    categories = ["evasion", "execution"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1059"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/execution_execution_of_a_file_downloaded_via_windows_openssh.toml"
    ]

    filter_apinames = set(["NtCreateFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, process):
        if process["process_name"].lower() == "scp.exe" or process["process_name"].lower() == "ssh.exe":
            if call["api"] == "NtCreateFile":
                filename = self.get_argument(call, "FileName").lower()
                if any(
                    filename.endswith("." + ext)
                    for ext in (
                        "exe",
                        "pif",
                        "scr",
                        "js",
                        "vbs",
                        "wsh",
                        "hta",
                        "cpl",
                        "jse",
                        "vbe",
                        "bat",
                        "cmd",
                        "dll",
                        "msi",
                        "ps1",
                    )
                ):
                    if self.pid:
                        self.mark_call()
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class ExecuteScriptsViaMicrosoftManagementConsole(Signature):
    name = "execute_scripts_via_microsoft_management_console"
    description = "Attempts to execute suspicious scripts via abusing an known XSS injection vulnerability in the APDS.dll"
    severity = 3
    categories = ["evasion", "execution"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1059", "T1059.005", "T1059.007"]
    references = [
        "https://www.elastic.co/security-labs/grimresource",
        "https://medium.com/@knownsec404team/from-http-domain-to-res-domain-xss-by-using-ie-adobes-pdf-activex-plugin-ba4f082c8199",
    ]

    filter_apinames = set(["NtCreateFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, process):
        if process["process_name"] == "mmc.exe":
            if call["api"] == "NtCreateFile":
                filename = self.get_argument(call, "FileName").lower()
                if filename.endswith("apds.dll"):
                    if self.pid:
                        self.mark_call()
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class ExecuteSuspiciousProcessesViaWindowsMSSQLService(Signature):
    name = "execute_suspicious_processes_via_windows_mssql_service"
    description = "Attempts to execute suspicious processes via Windows MSSQL service"
    severity = 2
    categories = ["evasion", "execution"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1059.001", "T1059.003"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/execution_suspicious_execution_from_mssql_service.toml"
    ]

    filter_apinames = set(["CreateProcessInternalW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, process):
        if process["process_name"] == "sqlservr.exe":
            if call["api"] == "CreateProcessInternalW":
                cmdline = self.get_argument(call, "CommandLine")
                lower = cmdline.lower()
                if any(proc in lower for proc in ("cmd.exe", "powershell.exe", "reg.exe")):
                    if self.pid:
                        self.mark_call()
                    self.detected = True

                elif "vpnbridge.exe" in lower:
                    if self.pid:
                        self.mark_call()
                    self.detected = True

                elif "certutil.exe" in lower and "-urlcache" in lower:
                    if self.pid:
                        self.mark_call()
                    self.detected = True

                elif "bitsadmin.exe" in lower and any(
                    arg in lower for arg in ("download", "transfer", "create", "addfile", "setnotifycmdline")
                ):
                    if self.pid:
                        self.mark_call()
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class CreateSuspiciousLNKFiles(Signature):
    name = "create_suspicious_lnk_files"
    description = "Attempts to create suspicious LNK files"
    severity = 2
    categories = ["evasion", "execution"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1204.001", "T1204.002"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/execution_suspicious_windows_shortcut_file_creation_or_modification.toml"
    ]

    filter_apinames = set(["NtWriteFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False
        self.badExtensions = (
            "pdf.lnk",
            "doc.lnk",
            "docx.lnk",
            "ppt.lnk",
            "pptx.lnk",
            "xls.lnk",
            "xlsx.lnk",
            "rtf.lnk",
            "jpg.lnk",
            "png.lnk",
            "html.lnk",
            "htm.lnk",
            "txt.lnk",
            "exe.lnk",
            "mp4.lnk",
            "avi.lnk",
            "bat.lnk",
            "rar.lnk",
            "zip.lnk",
            "img.lnk",
            "iso.lnk",
        )

    def on_call(self, call, process):
        if process["process_name"] in ("winrar.exe", "7zFM.exe"):
            if call["api"] == "NtWriteFile":
                fileBuf = self.get_raw_argument(call, "Buffer")
                fileLen = self.get_raw_argument(call, "Length")
                filepath = self.get_argument(call, "HandleName")
                if fileLen > 200000 and fileBuf.startswith("4c000000") and any(ext in filepath for ext in self.badExtensions):
                    if self.pid:
                        self.mark_call()
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class ExecuteSafeModeFromSuspiciousProcess(Signature):
    name = "execute_safe_mode_from_suspicious_process"
    description = "Attempts to enter the safe mode using bcdedit.exe from suspicious process"
    severity = 2
    categories = ["evasion", "execution"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1059.001", "T1059.003"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/impact_bcdedit_safe_mode_command_execution.toml"
    ]

    filter_apinames = set(["CreateProcessInternalW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False
        self.blacklistedProcesses = (
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "msaccess.exe",
            "mspub.exe",
            "outlook.exe",
            "fltldr.exe",
            "cscript.exe",
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cmd.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "mshta.exe",
            "msbuild.exe",
        )

    def on_call(self, call, process):
        if process["process_name"].lower() in self.blacklistedProcesses:
            if call["api"] == "CreateProcessInternalW":
                cmdline = self.get_argument(call, "CommandLine")
                lower = cmdline.lower()
                if "bcdedit" in lower and any(arg in lower for arg in ("minimal", "network", "safebootalternateshell")):
                    if self.pid:
                        self.mark_call()
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class AccessAutoLogonsViaRegistry(Signature):
    name = "access_auto_logons_via_registry"
    description = "Attempts to access AutoLogons credentials via registry value query"
    severity = 2
    categories = ["credentials"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1552", "T1552.001"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/credential_access_autologons_access_attempt_via_registry.toml"
    ]

    filter_apinames = set(["RegSetValueExW", "RegQueryValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False
        self.whitelistProcessPaths = (
            "\\windows\\system32\\logonui.exe",
            "\\sources\\setuphost.exe",
            "\\sources\\setupplatform.exe",
            "\\sources\\windowsupdatebox.exe",
            "\\windows\\system32\\svchost.exe",
            "\\windows\\system32\\wbem\\wmiprvse.exe",
            "\\windows\\syswow64\\wbem\\wmiprvse.exe",
            "\\windows\\system32\\musnotification.exe",
            "\\windows\\syswow64\\musnotification.exe",
            "\\windows\\system32\\wsmprovhost.exe",
            "\\windows\\system32\\conhost.exe",
            "\\windows\\system32\\securityhealthsystray.exe",
            "\\windows\\regedit.exe",
            "\\program files\\",
            "\\program files (x86)\\",
            "\\windows\\system32\\cmd.exe",
            "\\windows\\system32\\windowspowershell\\",
            "\\programdata\\microsoft\\windows defender\\platform\\",
            "\\users\\*\\appdata\\local\\microsoft\\onedrive\\onedrive.exe",
        )

    def on_call(self, call, process):
        if not any(path in process["module_path"].lower() for path in self.whitelistProcessPaths):
            if call["api"].startswith("RegQueryValueEx"):
                keyName = self.get_argument(call, "FullName")
                if "\\microsoft\\windows nt\\currentversion\\winlogon\\defaultpassword" in keyName.lower():
                    if self.pid:
                        self.mark_call()
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class CredentialAccessViaWindowsCredentialHistory(Signature):
    name = "credential_access_via_windows_credential_history"
    description = "Attempts to access Users Windows Credential History File that is used by Microsoft's DPAPI"
    severity = 2
    categories = ["credentials"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1555"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/credential_access_potential_credential_access_via_windows_credential_history.toml"
    ]
    evented = True

    filter_apinames = set(["NtCreateFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False
        self.whitelistProcessPaths = (
            "\\program files\\",
            "\\program files (x86)\\",
            "\\windows\\system32\\lsass.exe",
            "\\windows\\system32\\svchost.exe",
            "\\windows\\system32\\robocopy.exe",
            "\\windows\\ccmcache\\",
            "\\windows\\ccm\\",
            "\\windows\\explorer.exe",
            "\\programdata\\microsoft\\windows defender\\",
            "\\windows\\system32\\werfault.exe",
            "\\windows\\syswow64\\werfault.exe",
            "\\windows\\system32\\dllhost.exe",
            "\\windows\\system32\\sdclt.exe",
            "\\windows\\system32\\pickerhost.exe",
            "\\windows\\system32\\mrt.exe",
        )

    def on_call(self, call, process):
        if not any(path in process["module_path"].lower() for path in self.whitelistProcessPaths):
            if call["api"] == "NtCreateFile":
                fileName = self.get_argument(call, "FileName")
                handle = int(self.get_argument(call, "FileHandle"), 16)
                if handle and "\\microsoft\\protect\\credhist" in fileName.lower():
                    if self.pid:
                        self.mark_call()
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class AccessBootKeyViaRegistry(Signature):
    name = "access_boot_key_via_registry"
    description = (
        "Attempts to to read the registry values used to calculate the System BootKey to recover passwords and other secrets"
    )
    severity = 3
    categories = ["credentials"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1003.002", "T1003.004"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/credential_access_system_bootkey_registry_access.toml"
    ]

    filter_apinames = set(["RegSetValueExW", "RegQueryValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False
        self.whitelistProcessPaths = ("\\windows\\system32\\lsass.exe", "\\windows\\system32\\svchost.exe")
        self.regKeys = ("\\control\\lsa\\skew1", "\\control\\lsa\\jd", "\\control\\lsa\\jdlsa\\gbg")

    def on_call(self, call, process):
        if not any(path in process["module_path"].lower() for path in self.whitelistProcessPaths):
            if call["api"].startswith("RegQueryValueEx"):
                keyName = self.get_argument(call, "FullName")
                if any(key in keyName.lower() for key in self.regKeys):
                    if self.pid:
                        self.mark_call()
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class NetworkConnectionViaSuspiciousProcess(Signature):
    name = "network_connection_via_suspicious_process"
    description = "Attempts to make a network connection via suspicious process"
    severity = 2
    categories = ["evasion", "network"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1036", "T1055"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_network_connection_via_process_with_unusual_arguments.toml"
    ]

    filter_categories = set(["network"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False
        self.blacklisterProcesses = (
            "addinprocess.exe",
            "addinprocess32.exe",
            "addinutil.exe",
            "applaunch.exe",
            "aspnet_compiler.exe",
            "aspnet_regbrowsers.exe",
            "aspnet_regiis.exe",
            "aspnet_regsql.exe",
            "aspnet_state.exe",
            "aspnet_wp.exe",
            "caspol.exe",
            "comsvcconfig.exe",
            "csc.exe",
            "cvtres.exe",
            "datasvcutil.exe",
            "edmgen.exe",
            "ilasm.exe",
            "installutil.exe",
            "jsc.exe",
            "microsoft.workflow.compiler.exe",
            "msbuild.exe",
            "mscorsvw.exe",
            "ngen.exe",
            "ngentask.exe",
            "regasm.exe",
            "regsvcs.exe",
            "servicemodelreg.exe",
            "vbc.exe",
            "wsatconfig.exe",
            "dllhost.exe",
            "regsvr32.exe",
            "gpupdate.exe",
            "searchprotocolhost.exe",
            "msiexec.exe",
        )

    def on_call(self, call, process):
        if call["status"] and any(proc in process["process_name"] for proc in self.blacklisterProcesses):
            self.detected = True
            self.data.append({"suspicious_process": process["process_name"]})

    def on_complete(self):
        return self.detected


class SuspiciousExecutionViaDotnetRemoting(Signature):
    name = "suspicious_execution_via_dotnet_remoting"
    description = "Attempts to execute via DotNet system runtime remoting to execute malicious assembly via named pipes"
    severity = 2
    categories = ["bypass", "execution"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1218"]
    references = [
        "https://github.com/nettitude/Aladdin",
        "https://www.tiraniddo.dev/2017/07/dg-on-windows-10-s-executing-arbitrary.html",
    ]
    evented = True

    def run(self):
        cmdlines = self.results.get("behavior", {}).get("summary", {}).get("executed_commands", [])
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "addinprocess" in lower and "/guid" in lower and "/pid" in lower:
                self.data.append({"command": cmdline})
                return True

        return False


class UsesRestartManagerForSuspiciousActivities(Signature):
    name = "uses_restart_manager_for_suspicious_activities"
    description = "Uses Restart Manager Sessions for either process discovery or file encryption"
    severity = 3
    categories = ["evasion", "discovery"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1057", "T1486"]
    references = ["https://www.crowdstrike.com/en-us/blog/windows-restart-manager-part-2/"]

    filter_apinames = set(["RmStartSession"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.sessionKeys = 0

    def on_call(self, call, _):
        if call["api"] == "RmStartSession":
            sessionKey = self.get_argument(call, "SessionKey")
            if sessionKey:
                self.sessionKeys += 1

    def on_complete(self):
        if self.sessionKeys >= 100:
            return True
        return False
