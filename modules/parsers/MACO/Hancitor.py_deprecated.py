from cape_parsers.CAPE.Hancitor import extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="Hancitor", other=raw_config)

    for url in raw_config.get("address", []):
        parsed_result.http.append(MACOModel.Http(uri=url, usage="c2"))

    if "Build ID" in raw_config:
        parsed_result.identifier.append(raw_config["Build ID"])

    return parsed_result


class Hancitor(Extractor):
    author = "kevoreilly"
    family = "Hancitor"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
