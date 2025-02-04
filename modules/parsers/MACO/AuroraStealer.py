from cape_parsers.CAPE.community.AuroraStealer import extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="AuroraStealer", other=raw_config)
    if raw_config.get("C2"):
        # IP related to C2
        parsed_result.http.append(MACOModel.Http(hostname=raw_config["C2"], usage="c2"))

    return parsed_result


class AuroraStealer(Extractor):
    author = "kevoreilly"
    family = "AuroraStealer"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
