class UsesRemoteDesktopSession(Signature):
    name = "uses_remote_desktop_session"
    description = "Connects to/from or queries a remote desktop session"
    severity = 3
    confidence = 80
    categories = ["access"]
    authors = ["bartblaze"]
    minimum = "1.2"
    evented = True
    ttp = ["T1021"]

    evented = True

    def run(self):
        utilities = [
		"tscon ",
		"tscon.exe",
		"mstsc ",
		"mstsc.exe",
		"qwinsta ",
		"qwinsta.exe",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret
