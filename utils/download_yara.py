import glob
import json
import os
import re

import requests
from bs2json import BS2Json
from bs4 import BeautifulSoup

ROOT = "/opt/CAPEv2"

ANALYZER_YARA_SUBPATH = "/analyzer/windows/data/yara"
ANALYZER_YARA_PATH = f"{ROOT}{ANALYZER_YARA_SUBPATH}"

ANALYZER_YARA_URL = f"https://github.com/kevoreilly/CAPEv2/tree/master{ANALYZER_YARA_SUBPATH}"
ANALYZER_YARA_RAW_URL = f"https://raw.githubusercontent.com/kevoreilly/CAPEv2/master{ANALYZER_YARA_SUBPATH}/%s"

CAPE = "/CAPE"
BINARIES = "/binaries"
MACRO = "/macro"
MEMORY = "/memory"
MONITOR = "/monitor"
URLS = "/urls"
SERVER_SIDE_YARA_SUBPATH = "/data/yara"
SERVER_SIDE_YARA_PATH_DIRS = [CAPE, BINARIES, MACRO, MEMORY, MONITOR, URLS]
SERVER_SIDE_YARA_PATH = f"{ROOT}{SERVER_SIDE_YARA_SUBPATH}%s"

SERVER_SIDE_YARA_URL = f"https://github.com/kevoreilly/CAPEv2/tree/master{SERVER_SIDE_YARA_SUBPATH}%s"
SERVER_SIDE_YARA_RAW_URL = f"https://raw.githubusercontent.com/kevoreilly/CAPEv2/master{SERVER_SIDE_YARA_SUBPATH}%s"


YARA_REGEX = "([\w\-\d]+\.yar)"

yara_file_names = set()

# First, grab all of the YARA rules available at the analyzer subpath on GitHub
resp = requests.get(ANALYZER_YARA_URL)
resp.raise_for_status()  # raises exception when not a 2xx response
if resp.status_code != 204:
    try:
        if resp.headers["content-type"].strip().startswith("application/json"):
            page_content = json.loads(resp.content).get("payload", {}).get("tree", {}).get("items", [])
        elif resp.headers["content-type"].strip().startswith("text/html"):
            bs2json = BS2Json(resp.text)
            json_obj = bs2json.convert()
            payload_text = json_obj["html"]["body"]["div"][0]["div"][3]["div"]["main"]["turbo-frame"]["div"]["react-app"]["script"][
                "text"
            ]
            json_payload = json.loads(payload_text)
            page_content = json_payload.get("payload", {}).get("tree", {}).get("items", [])
        else:
            dataform = str(resp.content).strip("'<>() ").replace("'", '"')
            page_content = json.loads(dataform).get("payload", {}).get("tree", {}).get("items", [])
        for line in page_content:
            if not line:
                continue
            match = re.search(YARA_REGEX, line["name"])
            if match:
                yara_file_names.add(match.group(0))
    except Exception as e:
        print(e)

# Delete current yara files to make sure to remove old rules
yara_files = glob.glob("%s/*" % ANALYZER_YARA_PATH)
for f in yara_files:
    os.remove(f)
# Now, get the content for each YARA rule and write it to disk
for file_name in sorted(list(yara_file_names)):
    file_content = requests.get(ANALYZER_YARA_RAW_URL % file_name).text

    yara_file_path = os.path.join(ANALYZER_YARA_PATH, file_name)
    with open(yara_file_path, "w") as f:
        f.write(file_content)
    print(f"Successfully downloaded and wrote {yara_file_path}!")

print("\n\n\nDeep breath...\n\n\n")

# Reset
yara_file_names = set()

# Next, grab all of the YARA rules available at the server side subpaths on GitHub
for d in SERVER_SIDE_YARA_PATH_DIRS:
    resp = requests.get(SERVER_SIDE_YARA_URL % d)
    resp.raise_for_status()  # raises exception when not a 2xx response
    if resp.status_code != 204:
        try:
            if resp.headers["content-type"].strip().startswith("application/json"):
                page_content = json.loads(resp.content).get("payload", {}).get("tree", {}).get("items", [])
            elif resp.headers["content-type"].strip().startswith("text/html"):
                bs2json = BS2Json(resp.text)
                json_obj = bs2json.convert()
                payload_text = json_obj["html"]["body"]["div"][0]["div"][3]["div"]["main"]["turbo-frame"]["div"]["react-app"][
                    "script"
                ]["text"]
                json_payload = json.loads(payload_text)
                page_content = json_payload.get("payload", {}).get("tree", {}).get("items", [])
            else:
                dataform = str(resp.content).strip("'<>() ").replace("'", '"')
                page_content = json.loads(dataform).get("payload", {}).get("tree", {}).get("items", [])
            for line in page_content:
                if not line:
                    continue
                match = re.search(YARA_REGEX, line["name"])
                if match:
                    yara_file_names.add(match.group(0))
        except Exception as e:
            print(e)

    for line in page_content:
        if not line:
            continue
        match = re.search(YARA_REGEX, line["name"])
        if match:
            yara_file_subpath = os.path.join(d, match.group(0))
            yara_file_names.add(yara_file_subpath)

# Delete current yara files to make sure to remove old rules
yara_files = glob.glob("%s/*" % SERVER_SIDE_YARA_PATH)
for f in yara_files:
    os.remove(f)
# Now, get the content for each YARA rule and write it to disk
for file_name in sorted(list(yara_file_names)):
    file_content = requests.get(SERVER_SIDE_YARA_RAW_URL % file_name).text

    yara_file_path = os.path.join(SERVER_SIDE_YARA_PATH % file_name)
    with open(yara_file_path, "w") as f:
        f.write(file_content)
    print(f"Successfully downloaded and wrote {yara_file_path}!")
