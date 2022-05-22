import logging
from typing import List

log = logging.getLogger(__name__)


def convert_needed_to_hex(input) -> str:
    result = ""
    for i, char in enumerate(input):
        if 0 <= ord(char) <= 127:
            result += char
        else:
            # determine if the last char was also hex encoded
            if i > 0 and ord(input[i - 1]) > 127:
                # we don't need the "opening" pipe
                result += f"{hex(ord(char)).replace('0x', '', 1)}"
            else:
                # if not, then we need the opening pipe
                result += f"|{hex(ord(char)).replace('0x', '', 1)}"

            # if the next one isn't also going to need hex encoded, then close it.
            result += "|" if i > 0 and ord(input[i + 1]) <= 127 else " "
    return result


def build_serv_dicts(servs) -> set:
    result = set()
    for item in servs:
        for s in item:
            serv, port = s.split(":", 1)
            tmp_dict = {"server": serv, "port": port}
            result.add(tmp_dict)

    return result


def cents_trickbot(config_dict: dict, suricata_dict: dict, sid_counter: int, md5: int, date: str, task_link: str) -> List[str]:
    """Creates Suricata rules from extracted TrickBot malware configuration.

    :param config_dict: Dictionary with the extracted TrickBot configuration.
    :type config_dict: `dict`

    :param sid_counter: Signature ID of the next Suricata rule.
    :type sid_counter: `int`

    :param md5: MD5 hash of the source sample.
    :type md5: `int`

    :param date: Timestamp of the analysis run of the source sample.
    :type date: `str`

    :param task_link: Link to analysis task of the source sample.
    :type task_link: `str`

    :return List of Suricata rules (`str`) or empty list if no rule has been created.
    """
    log.debug("[CENTS] Config for TrickBot Starting")
    if not config_dict or not sid_counter or not md5 or not date or not task_link:
        log.debug("[CENTS] Config did not get enough data to run")
        return []

    next_sid = sid_counter
    rule_list = []
    servs = build_serv_dicts(config_dict.get("servs", []))
    # create a list of dicts which contain the server and port
    gtag = config_dict.get("gtag", "")
    ver = config_dict.get("ver", "")
    trickbot_c2_certs = set()
    log.debug("[CENTS - TrickBot] Looking for certs from %d c2 servers", len(servs))
    for s in servs:
        # see if the server and port are also in the tls certs
        matching_tls = list(
            filter(lambda x: x["dstip"] == s["server"] and str(x["dstport"]) == str(s["port"]), suricata_dict.get("tls", []))
        )
        log.debug("[CENTS - TrickBot] Found %d certs for %s", len(matching_tls), s)
        for tls in matching_tls:
            _tmp_obj = {"subject": tls.get("subject", None), "issuerdn": tls.get("issuerdn")}
            trickbot_c2_certs.add(_tmp_obj)

    log.debug("[CENTS - TrickBot] Building %d rules based on c2 certs", len(trickbot_c2_certs))
    for c2_cert in trickbot_c2_certs:
        rule = (
            f'alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CENTS Observed TrickBot C2 Certificate '
            f'(gtag {gtag[0]}, version {ver[0]})"; flow:established,to_client; '
        )
        if c2_cert.get("subject"):
            # if the subject has some non-ascii printable chars, we need to hex encode them
            suri_string = convert_needed_to_hex(c2_cert.get("subject"))
            rule += f'tls.cert_subject; content:"{suri_string}"; '
        if c2_cert.get("issuerdn"):
            # if the subject has some non-ascii printable chars, we need to hex encode them
            suri_string = convert_needed_to_hex(c2_cert.get("issuerdn"))
            rule += f'tls.cert_issuer; content:"{suri_string}"; '

        rule += f"reference:md5,{md5}; reference:url,{task_link}; sid:{next_sid}; rev:1; metadata:created_at {date};)"
        next_sid += 1

        rule_list.append(rule)

    log.debug("[CENTS - TrickBot] Returning built rules")
    return rule_list
