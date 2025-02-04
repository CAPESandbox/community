from cape_parsers.CAPE.core.Formbook import extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="Formbook", other=raw_config)

    if "C2" in raw_config:
        parsed_result.http.append(MACOModel.Http(uri=raw_config["C2"], usage="c2"))

    for decoy in raw_config.get("Decoys", []):
        parsed_result.http.append(MACOModel.Http(uri=decoy, usage="decoy"))

    return parsed_result


class Formbook(Extractor):
    author = "kevoreilly"
    family = "Formbook"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
