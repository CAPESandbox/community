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
        cmdlines = self.results.get("behavior").get("summary").get("executed_commands")
        for cmdline in cmdlines:
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
        if process["name"] in ("wscript.exe", "cscript.exe") and call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine")
            lower = cmdline.lower()
            if (
                "jave.exe" in lower
                and "-jar" in lower
                and any(arg in lower for arg in ("\\appdata\\", "\\public\\", "\\programdata\\"))
            ):
                self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False
