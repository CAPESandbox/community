# Copyright (C) 2020 ditekshen
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class NetworkCnCHTTPSGeneric(Signature):
    name = "network_cnc_https_generic"
    description = "Establishes an encrypted HTTPS connection"
    severity = 2
    categories = ["network", "encryption"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1032"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.httpverbs = [
            "GET",
            "POST",
            "ET /",
            "OST /",
        ]

    filter_apinames = set(["SslEncryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            for verb in self.httpverbs:
                if buff.startswith(verb):
                    self.match = True
                    self.data.append({"http_request": buff})

    def on_complete(self):
        return self.match

class NetworkCnCHTTPSSocialMedia(Signature):
    name = "network_cnc_https_socialmedia"
    description = "Establishes an encrypted HTTPS connection to a social media API"
    severity = 3
    categories = ["network", "encryption"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1032"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.domains = [
            "api.twitter.com",
            "cdn.discordapp.com",
            "api.telegram.org",
            "api.instagram.com",
            "graph.facebook.com",
            "wa.me",
            "gist.github.com",
            "raw.githubusercontent.com",
            "telete.in",
            "api.whatsapp.com",
            "api.vkontakte.ru",
            "api.vk.com"
        ]

    filter_apinames = set(["SslEncryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            for domain in self.domains:
                host_header = "Host: " + domain
                if host_header in buff:
                    self.match = True
                    self.data.append({"http_request": buff})
    
    def on_complete(self):
        return self.match

class NetworkCnCHTTPSPasteSite(Signature):
    name = "network_cnc_https_pastesite"
    description = "Establishes an encrypted HTTPS connection to a paste site"
    severity = 3
    categories = ["network", "encryption"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1032"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.domains = [
            "pastebin.com",
            "paste.ee",
            "pastecode.xyz",
            "rentry.co",
            "paste.nrecom.net",
            "hastebin.com",
            "privatebin.info",
            "penyacom.org",
            "controlc.com",
            "tiny-paste.com",
            "paste.teknik.io",
            "privnote.com",
            "hushnote.herokuapp.com",
            "justpaste.it",
            "stikked.ch",
            "dpaste.com",
        ]

    filter_apinames = set(["SslEncryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            for domain in self.domains:
                host_header = "Host: " + domain
                if host_header in buff:
                    self.match = True
                    self.data.append({"http_request": buff})
    
    def on_complete(self):
        return self.match

class NetworkCnCHTTPSURLShortenerSite(Signature):
    name = "network_cnc_https_urlshortener"
    description = "Establishes an encrypted HTTPS connection to a URL shortener site"
    severity = 3
    categories = ["network", "encryption"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1032"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.domains = [
            "bit.ly",
            "cutt.ly",
            "goo.gl",
            "www.shorturl.at",
            "n9.cl",
            "is.gd",
            "rb.gy",
            "long.af",
            "ykm.de",
            "ito.mx",
            "me2.do",
            "bit.do",
            "coki.me",
            "hyp.ae",
            "s.id",
        ]

    filter_apinames = set(["SslEncryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            for domain in self.domains:
                host_header = "Host: " + domain
                if host_header in buff:
                    self.match = True
                    self.data.append({"http_request": buff})
    
    def on_complete(self):
        return self.match

class NetworkCnCHTTPSTempStorageSite(Signature):
    name = "network_cnc_https_tempstorage"
    description = "Establishes an encrypted HTTPS connection to a temporary or anonymous storage site"
    severity = 3
    categories = ["network", "encryption"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1032"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.domains = [
            "send-anywhere.com",
            "sendgb.com",
            "volafile.org",
            "uploadfiles.io",
            "sendpace.com",
            "filedropper.com",
            "myairbridge.co",
            "u.teknik.io",
            "p.teknik.io",
            "upload.sexy",
            "digitalassets.ams3.digitaloceanspaces.com",
            "api.sendspace.com",
            "www.fileden.com",
            "a.pomf.cat",
            "dropmb.com",
            "transfer.sh",
            "1fichier.com",
        ]

    filter_apinames = set(["SslEncryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            for domain in self.domains:
                host_header = "Host: " + domain
                if host_header in buff:
                    self.match = True
                    self.data.append({"http_request": buff})
    
    def on_complete(self):
        return self.match

class NetworkCnCHTTPSUserAgent(Signature):
    name = "network_cnc_https_useragent"
    description = "Establishes an encrypted HTTPS connection containing a suspicious or fake User Agent"
    severity = 3
    categories = ["network", "encryption"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1032"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.useragents = [
            "AutoIt",
            "Mozilla/7",
            "AutoHotKey",
            "Moz5",
            "(iPhone;",
            "(iPad;",
            "(Android;",
            "like Mac OS X",
            "(Macintosh;",
            "(X11; Linux",
            "DiscordBot",
            "NSISDL",
            "InnoDownloadPlugin",
            "IEMobile",
            "Windows Phone OS",
            "(BlackBerry;",
        ]

    filter_apinames = set(["SslEncryptPacket"])
    
    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            for ua in self.useragents:
                if ua in buff:
                    self.match = True
                    self.data.append({"http_request": buff})
    
    def on_complete(self):
        return self.match

class NetworkCnCHTTPSTempURLDNS(Signature):
    name = "network_cnc_https_temp_urldns"
    description = "Establishes encrypted HTTPS connection to temporary URL or DNS service"
    severity = 3
    categories = ["network", "encryption"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1032"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.domains = [
            ".requestbin.net",
        ]

    filter_apinames = set(["SslEncryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            for domain in self.domains:
                if domain in buff:
                    self.match = True
                    self.data.append({"http_request": buff})
    
    def on_complete(self):
        return self.match

class NetworkCnCHTTPSPayload(Signature):
    name = "network_cnc_https_payload"
    description = "Downloads executable over encrypted HTTPS connection"
    severity = 3
    categories = ["network", "encryption"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1032"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        
    filter_apinames = set(["SslDecryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff and "MZ" in buff and "This program cannot be run in" in buff:
            self.match = True

    def on_complete(self):
        return self.match

class NetworkCnCHTTPSFreeWebHosting(Signature):
    name = "network_cnc_https_free_webshoting"
    description = "Establishes encrypted HTTPS connection to free web hosting service"
    severity = 3
    categories = ["network", "encryption"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1032"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.domains = [
            ".000webhostapp.com",
            ".repl.co",
            ".glitch.me",
        ]

    filter_apinames = set(["SslEncryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            for domain in self.domains:
                if domain in buff:
                    self.match = True
                    self.data.append({"http_request": buff})
    
    def on_complete(self):
        return self.match

class NetworkCnCSMTPSGeneric(Signature):
    name = "network_cnc_smtps_generic"
    description = "Encrypted SMTPS communication was detected"
    severity = 2
    categories = ["network", "encryption"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1032"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.smtpheaders = [
            "AUTH",
            "MAIL",
            "RCPT",
            "UTH login",
            "AIL FROM",
            "CPT TO",
        ]

    filter_apinames = set(["SslEncryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            for header in self.smtpheaders:
                if buff.startswith(header):
                    self.match = True
                    self.data.append({"smtp_header": buff})

            if "From: " in buff or "To: " in buff or "Subject: " in buff:
                self.match = True
                self.data.append({"smtp_header": buff})

    def on_complete(self):
        return self.match

class NetworkCnCSMTPSExfil(Signature):
    name = "network_cnc_smtps_exfil"
    description = "keylogger detected exfiltrating data via encrypted SMTPS connection"
    severity = 3
    categories = ["network", "encryption", "exfiltration", "infostealer", "RAT"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttp = ["T1020", "T1032", "T1041"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.found_orion = False
        self.found_phoenix = False
        self.found_hawkeye = False
        self.found_agentteslat1 = False
        self.found_agentteslat2 = False
        self.found_aspire = False
        self.found_m00nd3v = False
        self.found_masslogger = False
        self.found_firebirdrat = False
        self.found_snake = False

    filter_apinames = set(["SslEncryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            if "From: " in buff or "To: " in buff:
                self.data.append({"smtp_header": buff})
            if "Subject: " in buff:
                if "SGF3a0V5ZSBLZXlsb" in buff or "SGF3a0V5ZSBSZ" in buff or "HawkEye Keylogger" in buff or "HawkEye Reborn" in buff:
                    self.found_hawkeye = True
                if " Recovered " in buff:
                    self.found_agentteslat1 = True
                if "PSWD |" in buff or "Logs |" in buff or "Screenshot |" in buff:
                    self.found_phoenix = True
                if "Orion Logger" in buff or "Orion" in buff:
                    self.found_orion = True
                if "Subject: P_" in buff or "Subject: S_" in buff or "Subject: C_" in buff or "Subject: PW_" in buff or "Subject: CO_" in buff or "Subject: SC_" in buff or "Subject: KL_" in buff:
                    self.found_agentteslat2 == True
                if "AspireLogger" in buff or "Aspire" in buff:
                    self.found_aspire = True
                if "U3RlYWxlciBMb2dz" in buff or "Execution Alert!" in buff or "Password Monitoring" in buff or "KeyStroke Monitoring" in buff or "Screen Monitoring" in buff or "WebCam Monitoring" in buff or "Clipboard Monitoring" in buff:
                    self.found_m00nd3v = True
                if "MassLogger |" in buff:
                    self.found_masslogger = True
                if ": PASSWORDS" in buff:
                    self.found_firebirdrat = True
                if "Snake Keylogger" in buff or "| Snake" in buff:
                    self.found_snake = True
                if "Screen Capture" in buff or "Keylog" in buff:
                    self.match = True

    def on_complete(self):
        if self.found_orion:
            self.description = "{0} {1}".format("Orion", self.description)
            self.families = ["OrionKeylogger"]
            return True
        elif self.found_hawkeye:
            self.description = "{0} {1}".format("HawkEye", self.description)
            self.families = ["HawkEye"]
            return True
        elif self.found_phoenix:
            self.description = "{0} {1}".format("Phoenix", self.description)
            self.families = ["Phoenix"]
            return True
        elif self.found_agentteslat1:
            self.description = "{0} {1}".format("AgentTeslaV1", self.description)
            self.families = ["AgentTeslaV1"]
            return True
        elif self.found_agentteslat2:
            self.description = "{0} {1}".format("AgentTeslaV2", self.description)
            self.families = ["AgentTelaV2"]
            return True
        elif self.found_aspire:
            self.description = "{0} {1}".format("AspireLogger", self.description)
            self.families = ["AspireLogger"]
            return True
        elif self.found_m00nd3v:
            self.description = "{0} {1}".format("M00nD3v", self.description)
            self.families = ["M00nD3v"]
            return True
        elif self.found_masslogger:
            self.description = "{0} {1}".format("MassLogger", self.description)
            self.families = ["MassLogger"]
            return True
        elif self.found_firebirdrat:
            self.description = "{0} {1}".format("Firebird/Hive", self.description)
            self.families = ["FirebirdRAT"]
            return True
        elif self.found_snake:
            self.description = "{0} {1}".format("Snake Keylogger", self.description)
            self.families = ["SnakeKeylogger"]
            return True
        elif self.match:
            self.description = "{0} {1}".format("Generic", self.description)
            return True

        return False

class NetworkCnCHTTPSArchive(Signature):
    name = "network_cnc_https_archive"
    description = "Establishes an encrypted HTTPS connection to an internet archiving website"
    severity = 3
    categories = ["network", "encryption"]
    authors = ["bartblaze"]
    minimum = "1.3"
    ttp = ["T1032"]
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.domains = [
            "archive.org",
            "archive.is",
        ]

    filter_apinames = set(["SslEncryptPacket"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "Buffer")
        if buff:
            for domain in self.domains:
                host_header = "Host: " + domain
                if host_header in buff:
                    self.match = True
                    self.data.append({"http_request": buff})
    
    def on_complete(self):
        return self.match
