import base64
import logging
import os
import urllib.parse
from typing import Optional
from contextlib import suppress

from lib.cuckoo.common.abstracts import Processing
from data.scraper_safe_url_list import safe_url_list

HAVE_URLEXTRACT = False
with suppress(ImportError):
    from urlextract import URLExtract
    HAVE_URLEXTRACT = True

log = logging.getLogger(__name__)


def try_base64_decode(text: str, validate: bool = True) -> Optional[bytes]:
    result = None
    with suppress(Exception):
        result = base64.b64decode(text, validate=validate)

    return result

def force_decode(text: str, max_decode_depth: int) -> Optional[str]:
    for _ in range(max_decode_depth):
        new_text = text
        base64_decoded_text = try_base64_decode(text, validate=True)
        if base64_decoded_text:
            if not base64_decoded_text.isascii():
                return None

            new_text = base64_decoded_text.decode()

        new_text = urllib.parse.unquote(new_text)
        if new_text == text:
            break

        text = new_text

    return text


class HtmlScraper(Processing):
    def run(self):

        if not HAVE_URLEXTRACT:
            print("Missed optional dependency: poetry run pip install -r extra/optional_dependencies.txt")
            return

        log.debug('Started html dump processing')
        self.key = 'html_scraper'

        html_dump_path = os.path.join(self.analysis_path, 'htmldump', 'html_dump.dump')
        last_url_path = os.path.join(self.analysis_path, 'htmldump', 'last_url.dump')
        if not os.path.isfile(html_dump_path):
            log.debug('Dump File not found, nothing to process')
            return {}

        try:
            with open(html_dump_path, 'r') as f:
                html_dump = f.read()

            # Grab all potentially javascript strings (text between quotes)
            # and recursively decode them via base64 and urldecode
            decoded_strings = []
            potential_javascript_strings = html_dump.split("'")[1::2]
            for string in potential_javascript_strings:
                decoded_string = force_decode(string, max_decode_depth=5)

                if not decoded_string:
                    continue

                decoded_strings.append(decoded_string)

            decoded_strings_text = '\n'.join(decoded_strings)

            extractor = URLExtract()
            text_to_search = f'{decoded_strings_text}\n{html_dump}'
            addresses_in_html = set(extractor.find_urls(text_to_search, only_unique=True, with_schema_only=True))

            if os.path.exists(last_url_path):
                with open(last_url_path, 'r') as f:
                    addresses_in_html.add(f.read())

            filtered_addresses = {url.strip('\\x27') for url in addresses_in_html if not url.startswith(safe_url_list)}

            log.debug('Finished html dump processing')

            return {'addresses': list(filtered_addresses)}
        except Exception:
            log.exception('Html dump processing failed')

        return {}
