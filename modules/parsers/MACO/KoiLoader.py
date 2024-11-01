from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel
from cape_parsers.CAPE.community.KoiLoader import RULE_SOURCE, extract_config
from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="KoiLoader", other=raw_config)

    for c2_url in raw_config.get("C2", []):
        parsed_result.http.append(MACOModel.Http(uri=c2_url, usage="c2"))

    return parsed_result


class KoiLoader(Extractor):
    author = "kevoreilly"
    family = "KoiLoader"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    yara_rule = RULE_SOURCE

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
