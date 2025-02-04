from cape_parsers.CAPE.core.Enfal import extract_config, rule_source
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    # TODO: Assign fields to MACO model
    parsed_result = MACOModel(family="Enfal", other=raw_config)

    return parsed_result


class Enfal(Extractor):
    author = "kevoreilly"
    family = "Enfal"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
