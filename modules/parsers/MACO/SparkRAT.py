from cape_parsers.CAPE.community.SparkRAT import extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="SparkRAT", other=raw_config)

    url = f"http{'s' if raw_config['secure'] else ''}://{raw_config['host']}:{raw_config['port']}{raw_config['path']}"

    parsed_result.http.append(
        MACOModel.Http(
            uri=url,
            hostname=raw_config["host"],
            port=raw_config["port"],
            path=raw_config["path"],
        )
    )

    parsed_result.identifier.append(raw_config["uuid"])

    return parsed_result


class SparkRAT(Extractor):
    author = "kevoreilly"
    family = "SparkRAT"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
