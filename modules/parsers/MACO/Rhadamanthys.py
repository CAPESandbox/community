from cape_parsers.CAPE.core.Rhadamanthys import extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="Rhadamanthys", other=raw_config)
    parsed_result.http = [MACOModel.Http(hostname=raw_config["C2"], usage="c2")]

    return parsed_result


class Rhadamanthys(Extractor):
    author = "kevoreilly"
    family = "Rhadamanthys"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
