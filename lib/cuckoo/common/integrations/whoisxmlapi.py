import logging

import requests
from lib.cuckoo.common.config import Config

log = logging.getLogger()
externalservices_cfg = Config("externalservices")
apikey = externalservices_cfg.whoisxmlapi.apikey


def whoisxmlapi_lookup(host):
    if not externalservices_cfg.whoisxmlapi.enabled or not apikey:
        return {}

    result = {}
    log.debug("Performing WHOIS Query for IP/Domain: %s", host)
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={apikey}&domainName={host}&outputFormat=json"
    try:
        r = requests.get(url, verify=False)
        if r.ok:
            result = r.json()
    except Exception as e:
        log.error("whoismlapi.com exception: %s", str(e))

    return result
