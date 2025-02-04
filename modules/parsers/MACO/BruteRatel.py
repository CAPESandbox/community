from cape_parsers.CAPE.core.BruteRatel import extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="BruteRatel", other=raw_config)

    for url in raw_config["C2"]:
        for path in raw_config["URI"]:
            parsed_result.http.append(
                MACOModel.Http(
                    uri=url,
                    user_agent=raw_config["User Agent"],
                    port=raw_config["Port"],
                    path=path,
                    usage="c2",
                )
            )

    return parsed_result


class BruteRatel(Extractor):
    author = "kevoreilly"
    family = "BruteRatel"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
