from lib.cuckoo.common.abstracts import Signature


class PendingFileRenameOperations(Signature):
    name = "pendingfilerenameoperations_Operations"
    description = "Attempts to hijack existing resources for execution and persistence using PendingFileRename operation"
    severity = 3
    categories = ["evasion", "execution", "persistence"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1112", "T1562", "T1562.001"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_allowprotectedrenames_registry_modification.toml",
    ]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, process):
        if not any(path in process["module_path"] for path in ("\\Program Files\\", "\\Program Files (86)\\")):
            if call["api"] in ("RegSetValueExA", "RegSetValueExW"):
                regKeyPath = self.get_argument(call, "FullName").lower()
                buf = self.get_argument(call, "Buffer")
                if "allowprotectedrenames" in regKeyPath and buf == "1":
                    self.data.append({"regkey": regKeyPath})
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class DisableDriverViaHVCIDisallowedImages(Signature):
    name = "disable_driver_via_hvcidisallowedimages"
    description = "Attempt to disable a driver via HVCIDisallowedImages"
    severity = 3
    categories = ["evasion"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1112"]
    references = [
        "https://x.com/yarden_shafir/status/1822667605175324787",
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_attempt_to_disable_driver_via_hvcidisallowedimages.toml",
    ]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False

    def on_call(self, call, _):
        if call["api"] in ("RegSetValueExA", "RegSetValueExW"):
            regKeyPath = self.get_argument(call, "FullName").lower()
            buf = self.get_argument(call, "Buffer")
            if "hvcidisallowedimages" in regKeyPath and ".sys" in buf:
                self.data.append({"Value": buf})
                self.detected = True

    def on_complete(self):
        if self.detected:
            self.data.append({"Value": self.buf})
            return True
        return False


class DisableDriverViaBlocklist(Signature):
    name = "disable_driver_via_blocklist"
    description = "Attempt to disable a driver Microsoft policy that prevents a blacklist of known vulnerable drivers"
    severity = 3
    categories = ["evasion"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1112"]
    references = [
        "https://www.unknowncheats.me/forum/anti-cheat-bypass/524561-windows-11-blacklisteddrivers-fix.html",
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_attempt_to_disable_windows_driver_blocklist_via_registry.toml",
    ]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False
        self.falseProcess = ("securityhealthservice", "ikernel.exe")

    def on_call(self, call, process):
        if process["process_name"].lower() not in self.falseProcess:
            if call["api"] in ("RegSetValueExA", "RegSetValueExW"):
                regKeyPath = self.get_argument(call, "FullName").lower()
                buf = self.get_argument(call, "Buffer")
                if "\\ci\\config\\vulnerabledriverblocklistenable" in regKeyPath and buf == "0":
                    self.data.append({"regkey": regKeyPath})
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False


class DisableHypervisorProtectedCodeIntegrity(Signature):
    name = "disable_hypervisor_protected_code_integrity"
    description = "Attempt to disable Hypervisor-protected Code Integrity to load unsigned drivers"
    severity = 3
    categories = ["evasion"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1112"]
    references = [
        "https://www.unknowncheats.me/forum/anti-cheat-bypass/524561-windows-11-blacklisteddrivers-fix.html",
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_disabling_hypervisor_protected_code_integrity_via_registry.toml",
    ]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.detected = False
        self.falseProcess = (
            "deviceenroller.exe",
            "omadmclient.exe",
            "svchost.exe",
            "securityhealthservice.exe",
            "mbamessagecenter.exe",
            "aisuite3.exe",
            "ikernel.exe",
            "regedit.exe",
        )

    def on_call(self, call, process):
        if not process["process_name"].lower in self.falseProcess:
            if call["api"] in ("RegSetValueExA", "RegSetValueExW"):
                regKeyPath = self.get_argument(call, "FullName").lower()
                buf = self.get_argument(call, "Buffer")
                if (
                    any(
                        key in regKeyPath
                        for key in (
                            "\\deviceguard\\hypervisorenforcedcodeintegrity",
                            "\\deviceguard\\scenarios\\hypervisorenforcedcodeintegrity\\enabled",
                        )
                    )
                    and buf == "0"
                ):
                    self.data.append({"regkey": regKeyPath})
                    self.detected = True

    def on_complete(self):
        if self.detected:
            return True
        return False
