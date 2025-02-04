from cape_parsers.CAPE.core.QakBot import extract_config, rule_source
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="QakBot", other=raw_config)

    for address in raw_config.get("address", []) + raw_config.get("C2s", []):
        host, port = address.split(":")
        parsed_result.http.append(MACOModel.Http(hostname=host, port=port, usage="c2"))

    return parsed_result


class QakBot(Extractor):
    author = "kevoreilly"
    family = "QakBot"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
