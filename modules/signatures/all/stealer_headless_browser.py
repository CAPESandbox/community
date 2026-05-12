import re
from lib.cuckoo.common.abstracts import Signature

BROWSER_RE = re.compile(
    r'\\(?:chrome|brave|msedge|firefox|opera)\.exe',
    re.IGNORECASE
)

SUSPICIOUS_PARENT_RE = re.compile(
    r'\\(?:Temp|AppData|ProgramData|Users\\[^\\]+\\(?:AppData|Downloads)|Users\\Public)\\',
    re.IGNORECASE
)

LEGITIMATE_LAUNCHERS = re.compile(
    r'(?:GoogleUpdate|BraveUpdate|MicrosoftEdgeUpdate|BraveCrashHandler|setup|installer)\.exe$',
    re.IGNORECASE
)


class BrowserCredentialTheftHeadless(Signature):
    name = "browser_credential_theft_headless"
    description = (
        "Stealer credential extraction: browser(s) launched headless with logging suppressed "
        "from a suspicious parent directory. Malware spawns real browser binaries in silent "
        "headless mode to access saved passwords, cookies, and session tokens."
    )
    severity = 4
    weight = 5
    confidence = 80
    categories = ["infostealer", "credential_access"]
    authors = ["wmetcalf"]
    minimum = "1.2"
    ttps = ["T1555.003", "T1185"]
    references = ["CAPE task 7296"]
    evented = False

    def run(self):
        cmdlines = (
            self.results.get("behavior", {})
            .get("summary", {})
            .get("executed_commands", []) or []
        )

        # Find browsers launched headless with logging suppressed
        headless_browsers = set()
        for cmd in cmdlines:
            lower = cmd.lower()
            if not BROWSER_RE.search(cmd):
                continue
            if "--headless" not in lower:
                continue
            if "--disable-logging" not in lower and "--log-level=3" not in lower:
                continue
            m = BROWSER_RE.search(cmd)
            if m:
                headless_browsers.add(m.group(0).lower())
                self.data.append({"headless_cmd": cmd[:200]})

        if not headless_browsers:
            return False

        # Require suspicious parent — find via process tree
        suspicious_parent = None
        processes = self.results.get("behavior", {}).get("processes", []) or []
        proc_by_pid = {p["process_id"]: p for p in processes if p.get("process_id") is not None}

        for proc in processes:
            path = proc.get("module_path", "") or proc.get("process_name", "") or ""
            if not BROWSER_RE.search(path):
                continue
            parent_id = proc.get("parent_id")
            if parent_id is None:
                continue
            parent = proc_by_pid.get(parent_id)
            if parent:
                parent_path = parent.get("module_path", "") or ""
                if SUSPICIOUS_PARENT_RE.search(parent_path) and not LEGITIMATE_LAUNCHERS.search(parent_path):
                    suspicious_parent = parent_path
                    self.data.append({"suspicious_parent": parent_path})
                    break

        # Also accept if 3+ browsers launched headless (multi-browser sweep = high confidence
        # even without confirmed parent — covers cases where process tree is incomplete)
        if suspicious_parent or len(headless_browsers) >= 3:
            self.data.append({"browsers_targeted": sorted(headless_browsers)})
            return True

        return False
