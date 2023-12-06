from __future__ import absolute_import
import logging
import os
import time
from io import BytesIO
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile
from lib.core.config import Config

log = logging.getLogger(__name__)

HAVE_SELENIUM = False

try:
    from selenium import webdriver
    from selenium.common.exceptions import TimeoutException
    from selenium.webdriver.firefox.service import Service

    HAVE_SELENIUM = True
except Exception as ex:
    log.error(ex)

__author__ = "Jonathan Abrahamy"
__email__ = "jonathan@intezer.com"
__version__ = "0.0.1"
__date__ = "03MAY2022"


class HtmlScraper(Thread, Auxiliary):
    def __init__(self, options=None, config=None):
        Thread.__init__(self)
        Auxiliary.__init__(self, options, config)
        self.config = Config(cfg="analysis.conf")

        self.enabled = True
        if "html_scraper" in options:
            self.enabled = options["html_scraper"]

        self.driver_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "bin", "geckodriver.exe")

        self.browser = None
        self.browser_runtime = options.get("browser_runtime", 3)

    @staticmethod
    def upload_to_htmldump_folder(file_name: str, content: bytes):
        tmpio = BytesIO(content)

        nf = NetlogFile()
        nf.init(f"htmldump/{file_name}")
        # now upload to host from the StringIO
        for chunk in tmpio:
            nf.sock.send(chunk)
        nf.close()

    def scrape_html(self):
        if not HAVE_SELENIUM:
            log.debug("Selenium not installed on machine, not scraping", self.driver_path)
            return

        if not os.path.isfile(self.driver_path):
            log.debug("Web driver not found in path %s, not scraping", self.driver_path)
            return

        if not hasattr(self.config, "category") or self.config.category != "file":
            log.debug("Category is not file, not scraping", self.config.category)
            return

        if not hasattr(self.config, "file_type") or "HTML" not in self.config.file_type:
            log.debug("File is not html, not scraping", self.config.category)
            return

        try:
            file_path = os.path.join(os.environ["TEMP"] + os.sep, str(self.config.file_name))

            service = Service(self.driver_path)

            # This flag ensures that gecko driver will run without opening a cmd window
            service.creationflags = 0x08000000

            firefox_options = webdriver.FirefoxOptions()
            firefox_options.add_argument("--disable-gpu")
            firefox_options.headless = True

            self.browser = webdriver.Firefox(options=firefox_options, service=service)
            self.browser.set_page_load_timeout(10)

            sample_url = "file:///{}".format(os.path.abspath(file_path))
            try:
                self.browser.get(sample_url)
                time.sleep(self.browser_runtime)
            except TimeoutException:
                log.warning("Page load timed out")

            log.debug("Starting upload")
            self.upload_to_htmldump_folder("html_dump.dump", self.browser.page_source.encode())

            if not self.browser.current_url.startswith("file://"):
                self.upload_to_htmldump_folder("last_url.dump", self.browser.current_url.encode())

            log.debug("HTML scraped successfully")
        except Exception as e:
            log.error(e, exc_info=True)

    def run(self):
        if not self.enabled:
            return False

        self.scrape_html()
        return True

    def stop(self):
        if self.enabled:
            if self.browser:
                self.browser.quit()
            return True
        return False
