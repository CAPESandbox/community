# Copyright (C) 2020 bartblaze
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature


class EnablesWDigest(Signature):
    name = "enables_wdigest"
    description = "Enables WDigest to store credentials in plaintext"
    severity = 3
    categories = ["persistence", "credential_access", "credential_dumping"]
    authors = ["bartblaze"]
    minimum = "1.3"
    ttps = ["T1003", "T1112"]  # MITRE v6,7,8
    mbcs = ["OB0003", "OB0005"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        ret = False
        reg_indicators = [".*\\\\Control\\\\SecurityProviders\\\\Wdigest\\\\UseLogonCredential$"]

        for indicator in reg_indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                ret = True

        return ret


class VaultCmd(Signature):
    name = "vaultcmd_credentialaccess"
    description = "Lists credentials using VaultCmd"
    severity = 3
    categories = ["credentials", "credential_access"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1555"]
    reference = ["https://attack.mitre.org/techniques/T1555/004/"]

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "vaultcmd" in lower and "list" in lower:
                ret = True
                self.data.append({"command": cmdline})

        return ret


class CredWiz(Signature):
    name = "credwiz_credentialaccess"
    description = "Exports credentials using CredWiz"
    severity = 3
    categories = ["credentials", "credential_access"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1555"]
    reference = ["https://attack.mitre.org/techniques/T1555/"]

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if "credwiz" in lower and "keymgr" in lower:
                ret = True
                self.data.append({"command": cmdline})

        return ret


class AccessWindowsPasswordsVault(Signature):
    name = "access_windows_passwords_vault"
    description = "Attempts to access Vault passwords via PowerShell"
    severity = 3
    categories = ["credential_access"]
    authors = ["@para0x0dise"]
    minimum = "0.5"
    evented = True
    ttps = ["T1059"]
    references = [
        "https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/windows/credential_access_access_to_windows_passwords_vault_via_powershell.toml"
    ]

    filter_apinames = set(["CreateProcessInternalW"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()

        # Checking parent process for false positives.
        if pname == "keeperpasswordmanager.exe":
            if call["api"] == "CreateProcessInternalW":
                cmdline = self.get_argument(call, "CommandLine")
                lower = cmdline.lower()
                if any(arg in lower for arg in ("passwordvault", "retrievepassword", "retrieveall")):
                    return False

    def on_complete(self):
        for cmdline in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            lower = cmdline.lower()
            if "powershell" in lower and any(arg in lower for arg in ("passwordvault", "retrievepassword", "retrieveall")):
                return True
        return False
