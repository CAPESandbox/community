import concurrent.futures
import json
import os
import urllib.request
from typing import Tuple

# Reference: https://github.com/swimlane/pyattck#configuration
download_links = {
    "enterprise_attck_json": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "pre_attck_json": "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json",
    "mobile_attck_json": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    "ics_attck_json": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
    "nist_controls_json": "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_10_1/nist800_53_r4/stix/nist800-53-r4-controls.json",
    "generated_attck_json": "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/generated_attck_data.json",
    "generated_nist_json": "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json",
}


def download_json_file(tuple_argument: Tuple[str, str]):
    filename, download_url = tuple_argument
    with urllib.request.urlopen(download_url) as url:
        data = json.loads(url.read().decode())
        with open(os.path.join("data", "mitre", f"{filename}.json"), "w") as f:
            json.dump(data, f, separators=(",", ":"))
    print(f"Successfully saved file {filename}.json")


def update_files():
    with concurrent.futures.ThreadPoolExecutor(7) as executor:
        executor.map(download_json_file, download_links.items())


if __name__ == "__main__":
    update_files()
