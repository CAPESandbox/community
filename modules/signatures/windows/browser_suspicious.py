# Copyright (C) 2026 Kevin Ross, improvements from Gemini
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

import re
from lib.cuckoo.common.abstracts import Signature

class ExecutesHeadlessBrowser(Signature):
    name = "executes_headless_browser"
    description = "Executed a web browser in headless mode, possibly for C2 or evasion"
    severity = 3
    confidence = 80
    categories = ["command", "evasion", "c2"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1202", "T1564"] 
    mbcs = ["OB0009"]

    def run(self):
        ret = False
        browsers = [
            r"chrome\.exe",
            r"brave\.exe",
            r"opera\.exe",
            r"vivaldi\.exe",
            r"msedge\.exe",
            r"firefox\.exe"
        ]
        headless_flags = [
            r"--headless",
            r"-headless" 
        ]
        # Compile regexes for performance (Ignore Case)
        browser_regex = re.compile(r'(?:' + '|'.join(browsers) + r')', re.IGNORECASE)
        headless_regex = re.compile(r'(?:' + '|'.join(headless_flags) + r')', re.IGNORECASE)

        # Whitelist for known legitimate headless processes
        whitelist = [
            # Example: r"c:\\sandbox\\internal_tools\\legit_scraper\.py"
        ]

        for cmdline in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            lower_cmdline = cmdline.lower()

            if browser_regex.search(lower_cmdline):
                if headless_regex.search(lower_cmdline):
                    is_whitelisted = any(re.search(w, lower_cmdline) for w in whitelist)
                    
                    if not is_whitelisted:
                        ret = True
                        self.data.append({"command": cmdline})

        return ret


class SuspiciousBrowserArguments(Signature):
    name = "suspicious_browser_arguments"
    description = "Executed a browser with suspicious arguments"
    severity = 2
    confidence = 80
    categories = ["command", "evasion", "stealth", "defense_evasion"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1562", "T1564", "T1218"] 

    def run(self):
        ret = False
        
        # Target Web Browsers
        browsers = [
            r"chrome\.exe",
            r"brave\.exe",
            r"opera\.exe",
            r"vivaldi\.exe",
            r"msedge\.exe",
            r"firefox\.exe"
        ]

        suspicious_flags = {
            "security_bypass": [
                r"--no-sandbox",                    # Disables the browser's core security sandbox
                r"--disable-web-security",          # Disables Same-Origin Policy (SOP)
                r"--ignore-certificate-errors",     # Allows interception/MitM of HTTPS traffic
                r"--allow-running-insecure-content",# Bypasses mixed content warnings
                r"--disable-features=.*isolateorigins" # Disables site isolation
            ],
            "remote_control": [
                r"--remote-debugging-port",         # Opens the Chrome DevTools Protocol (CDP) for remote C2
                r"--remote-allow-origins",          # Allows external scripts to connect to the CDP
                r"--enable-automation"              # Used by Puppeteer/Selenium, suppresses some UI warnings
            ],
            "stealth_and_evasion": [
                r"--window-position=-\d+",          # e.g., --window-position=-32000 (Moves window off-screen)
                r"--mute-audio",                    # Prevents ad/video audio from alerting the user
                r"--disable-crash-reporter",        # Prevents Windows from catching browser crashes
                r"--disable-notifications",         # Suppresses push notifications
                r"--hide-scrollbars",               # UI hiding
                r"--no-first-run"                   # Bypasses the initial setup prompts
            ]
        }

        browser_regex = re.compile(r'(?:' + '|'.join(browsers) + r')', re.IGNORECASE)
        compiled_flags = {}
        for category, flags in suspicious_flags.items():
            compiled_flags[category] = re.compile(r'(?:' + '|'.join(flags) + r')', re.IGNORECASE)

        # Whitelist for known legitimate automated processes
        whitelist = [
            # Example: r"c:\\sandbox\\internal_tools\\legit_scraper\.py"
        ]

        for cmdline in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            lower_cmdline = cmdline.lower()

            if browser_regex.search(lower_cmdline):
                is_whitelisted = any(re.search(w, lower_cmdline) for w in whitelist)
                if is_whitelisted:
                    continue

                detected_categories = []
                for category, regex in compiled_flags.items():
                    if regex.search(lower_cmdline):
                        detected_categories.append(category)

                if detected_categories:
                    ret = True
                    self.data.append({
                        "command": cmdline,
                        "flagged_categories": detected_categories
                    })

        return ret
