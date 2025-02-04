from cape_parsers.CAPE.core.BuerLoader import extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="BuerLoader", other=raw_config)

    for c2 in raw_config["address"]:
        parsed_result.http.append(MACOModel.Http(hostname=c2, usage="c2"))
    return parsed_result


class BuerLoader(Extractor):
    author = "kevoreilly"
    family = "BuerLoader"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
