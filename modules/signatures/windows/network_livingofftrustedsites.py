# Copyright (C) 2025 Kevin Ross
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

class SuspiciousCommsTrustedSites(Signature):
    name = "suspicious_communication_trusted_site"
    description = "Suspicious communication with abused trusted site"
    severity = 2
    confidence = 50
    categories = ["living-off-trusted-sites", "C&C", "network"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True
    references = ["https://go.recordedfuture.com/hubfs/reports/cta-2023-0816.pdf", "https://lots-project.com/"]
    ttps = ["T1071"]  # MITRE v6,7,8

    filter_apinames = set(["GetAddrInfoExA", "GetAddrInfoExW", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.currenthandle = ""
        
        self.ignoreprocs = {
            "chrome.exe",
            "discord.exe",
            "dropbox.exe",
            "excel.exe",
            "firefox.exe",
            "iexplore.exe",
            "msaccess.exe",
            "msedge.exe",
            "mspub.exe",
            "msteams.exe",
            "onedrive.exe",
            "slack.exe",
            "steam.exe",
            "telegram.exe",
            "winword.exe",
        }
        
        self.lotsdomains = [
            "archive.ph",
            "discord.com",
            "discordapp.com",
            "docs.google.com",
            "drive.google.com",
            "dropbox.com",
            "firebaseapp.com",
            "gitee.com",
            "github.com",
            "githubusercontent.com",
            "github.io",
            "gitlab.com",
            "herokuapp.com",
            "notion.site",
            "notion.so",
            "onedrive.live.com",
            "paste.ee",
            "pastebin.",
            "pastetext.net",
            "slack-files.com",
            "slack.com",
            "steamcommunity.com",
            "reddit.com",
            "telegram.org",
            "telegra.ph",
            "t.me",
            "wetransfer.com",
            "workers.dev",
            "youtube.com",
        ]

    def on_call(self, call, process):
        if call["api"].startswith("GetAddrInfoEx"):
            servername = self.get_argument(call, "Name")
            for lotdomain in self.lotsdomains:
                if lotdomain in servername:
                    self.mark_call()
                    self.ret = True
                    
        if call["api"].startswith("WinHttpConnect"):
            servername = self.get_argument(call, "ServerName")
            for lotdomain in self.lotsdomains:
                if lotdomain in servername:
                    self.mark_call()
                    self.ret = True
                    self.currenthandle = str(call["return"])
                    
        if call["api"] in ["WinHttpOpenRequest", "WinHttpSendRequest"]:
            if self.currenthandle and self.currenthandle not in ["0x00000000"]:
                handle = self.get_argument(call, "InternetHandle")
                if handle == self.currenthandle:
                    self.mark_call()
                    self.currenthandle = str(call["return"])
              
    def on_complete(self):
        return self.ret
