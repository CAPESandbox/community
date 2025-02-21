from cape_parsers.CAPE.core.Azorult import YARA_RULES, extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    return MACOModel(
        family="Azorult",
        http=[MACOModel.Http(hostname=raw_config["address"])],
        other=raw_config,
    )


class Azorult(Extractor):
    author = "kevoreilly"
    family = "Azorult"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family) or YARA_RULES

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
