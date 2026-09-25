from lib.cuckoo.common.abstracts import Signature

filesDeleted = (
    "Log.zip",
    "sqlite3.dll",
    "ff-funcs.zip",
    "passwords.txt",
    "CC.txt",
    "chrome_cookie.txt",
    "firefox_cookie.txt",
    "chrome_autofill.txt",
    "machineinfo.txt",
    "screen.png",
)

filesSearched = (
    r"AppData\\Roaming\\WaterFox\\Profiles\\*",
    r"AppData\\Roaming\\WaterFox\\Profiles\\*",
    r"AppData\\Roaming\\Mozilla\\SeaMonkey\\Profiles\\*",
    r"AppData\\Roaming\\Mozilla\\SeaMonkey\\Profiles\\*",
    r"AppData\\Roaming\\Moonchild Productions\\Pale Moon\\Profiles\\*",
    r"AppData\\Roaming\\Thunderbird\\Profiles\\*",
    r"AppData\\Roaming\\Thunderbird\\Profiles\\*",
    r"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates\\*",
    r"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\CRLs\\*",
    r"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\CTLs\\*",
    r"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates\\*",
    r"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\CRLs\\*",
    r"AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\CTLs\\*",
    r"AppData\\Local\\Google\\Chrome\\User Data\\*",
    r"AppData\\Local\\Xpom\\User Data\\*",
    r"AppData\\Local\\Comodo\\Dragon\\User Data\\*",
    r"AppData\\Local\\Amigo\\User Data\\*",
    r"AppData\\Local\\Orbitum\\User Data\\*",
    r"AppData\\Local\\Bromium\\User Data\\*",
    r"AppData\\Local\\Nichrome\\User Data\\* ",
    r"AppData\\Local\\RockMelt\\User Data\\*",
    r"AppData\\Local\\360Browser\\Browser\\User Data\\*",
    r"AppData\\Local\\Vivaldi\\User Data\\*",
    r"AppData\\Roaming\\Opera Software\\*",
    r"AppData\\Local\\Go!\\User Data\\*",
    r"AppData\\Local\\Sputnik\\Sputnik\\User Data\\*",
    r"AppData\\Local\\Kometa\\User Data\\*",
    r"AppData\\Local\\uCozMedia\\Uran\\User Data\\*",
    r"AppData\\Local\\QIP Surf\\User Data\\*",
    r"AppData\\Local\\Epic Privacy Browser\\User Data\\*",
    r"AppData\\Local\\CocCoc\\Browser\\User Data\\*",
    r"AppData\\Local\\CentBrowser\\User Data\\*",
    r"AppData\\Local\\7Star\\7Star\\User Data\\*",
    r"AppData\\Local\\Elements Browser\\User Data\\*",
    r"AppData\\Local\\TorBro\\Profile\\*",
    r"AppData\\Local\\Suhba\\User Data\\*",
    r"AppData\\Local\\Safer Technologies\\Secure Browser\\User Data\\*",
    r"AppData\\Local\\Rafotech\\Mustang\\User Data\\*",
    r"AppData\\Local\\Superbird\\User Data\\*",
    r"AppData\\Local\\Chedot\\User Data\\*",
    r"AppData\\Local\\Torch\\User Data\\*",
)

infoWrited = (
    "Raccoon Stealer",
    "Build compiled on",
    "Launched at:",
    "Bot_ID:",
    "System Information:",
    "System Language:",
    "Username:",
    "IP:",
    "Windows version:",
    "Product name:",
    "System arch:",
    "CPU:",
    "RAM:",
    "Screen resolution:",
    "Display devices:",
    "Installed Apps:",
)


class raccoon(Signature):
    name = "raccoon_behavior"
    description = "Detects Raccoon Behavior"
    weight = 3
    severity = 3
    categories = ["infostealer"]
    families = ["Raccoon"]
    authors = ["@NaxoneZ"]
    minimum = "1.2"
    evented = True

    # Sample List
    # Raccoon:
    # 1. 726aa7c9d286afab16c956639ffe01a47ce556bc893f46d487b3148608a019d7 (variant1)

    filter_apinames = set(["DeleteFileW", "FindFirstFileExW", "NtWriteFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.badness_filesSearched = 0
        self.badness_filesDeleted = 0
        self.badness_infoWrited = 0

    def on_call(self, call, process):
        if call["api"] == "DeleteFileW":
            node = self.get_argument(call, "FileName")
            for i in filesDeleted:
                if i in node:
                    self.badness_filesDeleted += 1
                    if self.pid:
                        self.mark_call()

        if call["api"] == "FindFirstFileExW":
            node = self.get_argument(call, "FileName")
            for i in filesSearched:
                if i in node:
                    self.badness_filesSearched += 1
                    if self.pid:
                        self.mark_call()

        if call["api"] == "NtWriteFile":
            node = self.get_argument(call, "Buffer")
            for i in infoWrited:
                if i in node:
                    self.badness_infoWrited += 1
                    if self.pid:
                        self.mark_call()

    def on_complete(self):
        if self.badness_filesSearched > 50 and self.badness_filesDeleted > 9 and self.badness_infoWrited > 15:
            return True
        else:
            return False


class RaccoonInfoStealerMutex(Signature):
    name = "asyncrat_mutex"
    description = "Creates known Raccoon Infostealer mutex"
    severity = 3
    categories = ["infostealer", "keylogger", "rat"]
    families = ["Raccoon"]
    authors = ["andreiminca"]
    minimum = "1.3"
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["OC0003", "C0042"]  # micro-behaviour

    def run(self):
        indicators = [
            ".*m\\$V1-xV4v$",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True, all=True)
            if match:
                for mut in match:
                    self.data.append({"mutex": mut})
                return True

        return False
