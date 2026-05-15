import os
from lib.cuckoo.common.abstracts import Signature


class COMSpawnedProcess(Signature):
    name = "com_spawned_process"
    description = (
        "Office application COM-activated a suspicious process via DCOM broker — "
        "the logical parent-child relationship is hidden behind svchost (LethalHTA / OLE embedding pattern)"
    )
    severity = 3
    weight = 3
    confidence = 85
    categories = ["behavior", "evasion"]
    authors = ["wmetcalf"]
    minimum = "1.2"
    ttps = ["T1559.001", "T1218.005"]
    evented = False

    OFFICE_ACTIVATORS = {
        "excel.exe", "winword.exe", "powerpnt.exe", "outlook.exe",
        "msaccess.exe", "mspub.exe", "visio.exe",
    }

    def run(self):
        # Only report confirmed COM-spawned subprocesses visible in the enriched tree.
        # Requiring com_logical_parent_pid avoids noise from normal JScript/WMI activations.
        def walk(nodes):
            for node in nodes:
                lpid = node.get("com_logical_parent_pid")
                lname = (node.get("com_logical_parent_name") or "").lower()
                if lpid and os.path.basename(lname) in self.OFFICE_ACTIVATORS:
                    self.data.append({
                        "spawned": "%s (pid %s)" % (node.get("name"), node.get("pid")),
                        "logical_parent": "%s (pid %s)" % (
                            node.get("com_logical_parent_name"), lpid),
                        "via": node.get("com_progid") or node.get("com_clsid", ""),
                    })
                walk(node.get("children") or [])

        walk((self.results.get("behavior") or {}).get("processtree") or [])
        return bool(self.data)
