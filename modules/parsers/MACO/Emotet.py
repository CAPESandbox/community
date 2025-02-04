from cape_parsers.CAPE.core.Emotet import extract_config, rule_source
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="Emotet", other=raw_config)

    for c2_address in raw_config.get("address", []):
        parsed_result.http.append(MACOModel.Http(uri=c2_address, usage="c2"))

    if "RC4 public key" in raw_config:
        parsed_result.encryption.append(MACOModel.Encryption(algorithm="RC4", public_key=raw_config["RSA public key"]))

    parsed_result.other = {k: raw_config[k] for k in raw_config.keys() if k not in ["address", "RSA public key"]}

    return parsed_result


class Emotet(Extractor):
    author = "kevoreilly"
    family = "Emotet"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
