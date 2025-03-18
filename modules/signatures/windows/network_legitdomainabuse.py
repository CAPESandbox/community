# Copyright (C) 2024 Kevin Ross
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


class LegitDomainAbuse(Signature):
    name = "legitimate_domain_abuse"
    description = "Connection to a legitimate domain from an unexpected process"
    severity = 2
    categories = ["network", "living-off-trusted-sites"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1102"]  # MITRE v6,7,8
    references = ["https://go.recordedfuture.com/hubfs/reports/cta-2023-0816.pdf", "https://lots-project.com/"]

    filter_apinames = set(["GetAddrInfoExW", "InternetConnectA", "InternetConnectW", "UrlDownloadToFile", "WinHttpConnect"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

        self.ignoreprocs = [
            "acrobat.exe",
            "acrord32.exe",
            "acrord64.exe",
            "chrome.exe",
            "discord.exe",
            "excel.exe",
            "firefox.exe",
            "iexplore.exe",
            "msedge.exe",
            "onedrive.exe",
            "onenote.exe",
            "outlook.exe",
            "powerpnt.exe",
            "safari.exe",
            "slack.exe",
            "teams.exe",
            "telegram.exe",
            "winword.exe",
        ]

        self.legitdomains = [
            "1drv.com",
            "apimocha.com",
            "api.telegram.org",
            "azurewebsites.net",
            "beeceptor.com",
            "bitbucket.io",
            "bitbucket.org",
            "bit.ly",
            "cloudapp.azure.com",
            "cloudapp.net",
            "cloudfront.net",
            "discord.com",
            "discordapp.com",
            "docs.google.com",
            "drive.google.com",
            "dropbox.com",
            "filetransfer.io",
            "firebaseapp.com",
            "firebasestorage.googleapis.com",
            "githubusercontent.com",
            "github.com",
            "gitlab.com",
            "herokuapp.com",
            "infinityfreeapp.com",
            "mediafire.com",
            "mega.nz",
            "mockapi.io",
            "mockbin.io",
            "mockoon.com",
            "mocky.io",
            "notion.com",
            "notion.so",
            "notion.site",
            "ngrok.io",
            "onedrive.live.com",
            "pastebin.",
            "paste.ee",
            "pastetext.net",
            "pastes.io",
            "pcloud.com",
            "reddit.com",
            "sendspace.com",
            "slack.com",
            "slack-files.com",
            "storage.googleapis.com",
            "trycloudflare.com",
            "wetransfer.com",
            "wiremock.org",
            ".workers.dev",
        ]

    def on_call(self, call, process):
        if call["api"] == "GetAddrInfoExW":
            pname = process["process_name"]
            if pname.lower() not in self.ignoreprocs:
                server = self.get_argument(call, "Name")
                for domain in self.legitdomains:
                    if domain in server:
                        self.mark_call()
                        self.ret = True

        if call["api"].startswith("InternetConnect") or call["api"] == "WinHttpConnect":
            pname = process["process_name"]
            if pname.lower() not in self.ignoreprocs:
                server = self.get_argument(call, "ServerName")
                for domain in self.legitdomains:
                    if domain in server:
                        self.mark_call()
                        self.ret = True

        if call["api"] == "UrlDownloadToFile":
            pname = process["process_name"]
            if pname.lower() not in self.ignoreprocs:
                server = self.get_argument(call, "Url")
                for domain in self.legitdomains:
                    if domain in server:
                        self.mark_call()
                        self.ret = True

    def on_complete(self):
        return self.ret
