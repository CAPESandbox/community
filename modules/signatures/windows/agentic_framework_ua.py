# Copyright (C) 2026 bartblaze
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

from lib.cuckoo.common.abstracts import Signature


class NetworkARTEXUserAgent(Signature):
    name = "artex_useragent"
    description = "ARTEX user-agent, indicates use of an agentic framework"
    severity = 3
    categories = ["network"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071"]
    reference = ["https://github.com/unixfreaxjp/malwaremustdie/tree/master/etc/artex-stix-osquery-sigma-kql-snort-suricata-yara"]

    filter_apinames = set(["InternetOpenA", "InternetOpenW", "WinHttpOpen"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.matches = []

        self.useragents = [
            "artex-audit/1.0",
            "artex-enrich/1.0",
            "artex-i21861-canary",
            "artex-pentest/1.0",
            "artex-readonly/1.0",
            "artex-spawn/1",
            "artex-verify/1.0",
            "artex-worker/1.0",
            "artex/1.0",
            "artex-authorized-pentest",
            "artexverify/1.0",
            "mozilla/5.0 (artex)",
            "mozilla/5.0 artex",
            "scopeweaver",
            "spa-api-recon",
            "Mozilla/5.0 (spa-api-recon)",
            "Mozilla/5.0 (spa-api-recon spider)",

        ]

    def on_call(self, call, process):
        if call["api"] in ("InternetOpenA", "InternetOpenW"):
            useragent = self.get_argument(call, "Agent")
        elif call["api"] == "WinHttpOpen":
            useragent = self.get_argument(call, "UserAgent")
        else:
            return

        if not useragent:
            return

        for indicator in self.useragents:
            if indicator in useragent.lower():
                entry = (process["process_name"], useragent)

                if entry not in self.matches:
                    self.matches.append(entry)

                    if self.pid:
                        self.mark_call()

                return

    def on_complete(self):
        for process, useragent in self.matches:
            self.data.append(
                {
                    "process": process,
                    "user-agent": useragent,
                }
            )

        return bool(self.data)


class NetworkHexStrikeUserAgent(Signature):
    name = "network_hexstrike_useragent"
    description = "HexStrike user-agent, indicates use of an agentic framework"
    severity = 3
    categories = ["network"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071"]

    filter_apinames = set(["InternetOpenA", "InternetOpenW", "WinHttpOpen"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.matches = []

        self.useragents = [
            "hexstrike-browseragent/1.0",
            "hexstrike-http-framework/1.0",
        ]

    def on_call(self, call, process):
        if call["api"] in ("InternetOpenA", "InternetOpenW"):
            useragent = self.get_argument(call, "Agent")
        elif call["api"] == "WinHttpOpen":
            useragent = self.get_argument(call, "UserAgent")
        else:
            return

        if not useragent:
            return

        for indicator in self.useragents:
            if indicator in useragent.lower():
                entry = (process["process_name"], useragent)

                if entry not in self.matches:
                    self.matches.append(entry)

                    if self.pid:
                        self.mark_call()

                return

    def on_complete(self):
        for process, useragent in self.matches:
            self.data.append(
                {
                    "process": process,
                    "user-agent": useragent,
                }
            )

        return bool(self.data)


class NetworkCyberStrikeAIUserAgent(Signature):
    name = "network_cyberstrikeai_useragent"
    description = "CyberStrikeAI user-agent, indicates use of an agentic framework"
    severity = 3
    categories = ["network"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071"]

    filter_apinames = set(["InternetOpenA", "InternetOpenW", "WinHttpOpen"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.matches = []

        self.useragents = [
            "mozilla/5.0 (compatible; cyberstrikeai-webshell/1.0)",
        ]

    def on_call(self, call, process):
        if call["api"] in ("InternetOpenA", "InternetOpenW"):
            useragent = self.get_argument(call, "Agent")
        elif call["api"] == "WinHttpOpen":
            useragent = self.get_argument(call, "UserAgent")
        else:
            return

        if not useragent:
            return

        for indicator in self.useragents:
            if indicator in useragent.lower():
                entry = (process["process_name"], useragent)

                if entry not in self.matches:
                    self.matches.append(entry)

                    if self.pid:
                        self.mark_call()

                return

    def on_complete(self):
        for process, useragent in self.matches:
            self.data.append(
                {
                    "process": process,
                    "user-agent": useragent,
                }
            )

        return bool(self.data)

