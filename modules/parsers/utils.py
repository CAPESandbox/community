import os

import requests

# Raw file download template (default to Github-based raw download URL)
CAPE_RAW_DOWNLOAD_TEMPLATE = os.environ.get(
    "CAPE_RAW_DOWNLOAD_TEMPLATE",
    "https://raw.githubusercontent.com/kevoreilly/CAPEv2/refs/heads/master/data/yara/CAPE/{family}.yar",
)


def get_YARA_rule(family: str) -> str | None:
    root = os.path.join(os.path.dirname(__file__))
    maco_yara_folder = os.path.join(root, "yara")
    # Check to see if the rules local to MACO extractors exist (this can be rules cached from a previous run)
    if not os.path.exists(os.path.join(root, "yara")):
        os.makedirs(maco_yara_folder)

    # YARA rule paths that differ based on relativity to the MACO extractor
    maco_yara_path = f"{maco_yara_folder}/{family}.yar"
    cape_yara_path = os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")

    if os.path.exists(maco_yara_path):
        # Return rule that seems to be directly related to MACO extractor
        with open(maco_yara_path) as f:
            return f.read()
    # Check to see if the rule exists in a CAPE or CAPE-like directory structure
    elif os.path.exists(cape_yara_path):
        # Return the content of local YARA rule
        with open(cape_yara_path) as f:
            return f.read()

    try:
        # Local rule doesn't exist, but maybe we can retrieve the corresponding core rule from CAPEv2
        # NOTE: This won't work in an air-gapped environment unless a mirror exists
        resp = requests.get(CAPE_RAW_DOWNLOAD_TEMPLATE.format(family=family), timeout=10)
        if resp.ok:
            # Cache the rule on disk
            with open(maco_yara_path, "w") as f:
                f.write(resp.text)
            return resp.text
    except Exception as e:
        # No rule to be found, assume that extractor has proper exception handling or the rule is embedded
        return
