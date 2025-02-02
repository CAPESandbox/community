from lib.cuckoo.common.abstracts import Signature


class DeletesExecutedFiles(Signature):
    name = "deletes_consolehost_history"
    description = "Deletes PowerShell Console History to conceal the action undertaken during an intrusion"
    severity = 3
    categories = ["stealth"]
    authors = ["@para0x0dise"]
    minimum = "1.2"
    ttps = ["T1070.003"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/defense_evasion_suspicious_powershell_console_history_deletion.toml"
    ]
    evented = True

    filter_apinames = set(["NtDeleteFile", "DeleteFileA", "DeleteFileW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.isDeleted = False
        self.blacklistedApps = (
            "powershell.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "winword.exe",
            "excel.exe",
        )
        self.blacklistedPaths = ["\\users\\", "\\windows\\temp\\", "\\programdata\\", "\\windows\\microsoft.net\\"]

    def on_call(self, call, process):
        if call["api"] in ("NtDeleteFile", "DeleteFileA", "DeleteFileW"):
            if "ConsoleHost_history.txt" in self.get_argument(call, "FileName"):
                self.isDeleted = True
                if self.pid:
                    self.mark_call()
                return

    def on_complete(self):

        # Verify True Positives
        if self.isDeleted:
            for proc in self.results.get("behavior", {}).get("processtree", []):
                if proc.get("name") in self.blacklistedApps or proc["module_path"].lower() in self.blacklistedPaths:
                    return True
        return False
