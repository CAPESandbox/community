import json

import requests

names = list()
malpedia_url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json"

r = requests.get(malpedia_url)
if r.ok:
    names = [v["value"] for v in r.json().get("values") or []]
    if names:
        open("malpedia.json", "wt").write(json.dumps(names))
