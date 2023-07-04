import re
import os
import json

import requests

import modules.signatures
from lib.cuckoo.core.plugins import list_plugins
from lib.cuckoo.core.plugins import import_package
from lib.cuckoo.common.abstracts import CUCKOO_ROOT


def mapMitre(oldID):
    try:
        response = requests.get(f"https://attack.mitre.org/techniques/{oldID}")
    except Exception as e:
        print(e)
        return oldID

    if response.status_code == 200:
        match1 = re.search(rb'url=([^"]+)"', response.content)
        if match1:
            url = match1.group(1).decode("utf-8")
            pattern = r"\/techniques\/(\w+)(?:\/(\d+))?"
            matches = re.search(pattern, url)
            if matches:
                ttp_id = matches.group(1)
                sub_id = matches.group(2) if matches.group(2) else ""
                # Create the final output with TTP ID and sub ID
                final_output = f"{ttp_id}.{sub_id}" if sub_id else ttp_id
                return final_output  # Output: i.e. T1218.004 if sub ID exists, otherwise T1218

    return oldID


if __name__ == "__main__":
    ttpDict = {}
    ttps_map_file = os.path.join(CUCKOO_ROOT, "data", "mitre", "TTPs.json")
    if os.path.exists(ttps_map_file):
        try:
            ttpDict = json.loads(open(ttps_map_file, "r").read())
        except Exception as e:
            print("Can't load TTPs.json file", e)

    import_package(modules.signatures)
    for sig in list_plugins(group="signatures"):
        if not sig.ttps:
            continue
        for ttp in sig.ttps:
            if "." in ttp or "U" in ttp or "S" in ttp:
                continue
            print(f"Fetching update for {sig.name} and TTP: {ttp}")
            ttpDict[ttp.upper()] = mapMitre(ttp)

    # Save the configuration to a file
    open(ttps_map_file, "w").write(json.dumps(ttpDict, indent=4))
    print("Done")
    # print(mapMitre("T1215"))
