#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
# import asyncio
import logging
import os
import smtplib
import sys
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from smtpd import SMTPServer

import aiosmtpd.controller

# CAPE root
sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))
from lib.cuckoo.common.config import Config

email_config = Config("smtp_sinkhole")

class CustomSMTPHandler:
    async def handle_DATA(self, server, session, envelope):
        """Custom mail processing used to save mails to disk."""
        # Save message to disk only if path is passed.
        timestamp = datetime.now()
        if self.mail_dir:
            file_name = "%s" % timestamp.strftime("%Y%m%d%H%M%S")

            # Duplicate check.
            i = 0
            while Path(os.path.join(self.mail_dir, file_name + str(i))).exists():
                i += 1

            file_name += str(i)
            with open(os.path.join(self.mail_dir, file_name), "wb") as mail:
                mail.write(envelope.content)

        # Forward message to specific email address
        if self.forward and email_config:
            try:
                timestamp = datetime.now()
                msg = MIMEMultipart()
                msg["Subject"] = "Email from smtp sinkhole: {0}".format(timestamp.strftime("%Y-%m-%d %H:%M:%S"))
                msg["From"] = email_config.email["from"]
                msg["To"] = email_config.email["to"]
                part = MIMEBase("application", "octet-stream")
                part.set_payload(envelope.content)
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", 'attachment; filename="cape.eml"')
                msg.attach(part)
                server = smtplib.SMTP_SSL(email_config.email["server"], int(email_config.email["port"]))
                server.login(email_config.email["user"], email_config.email["password"])
                server.set_debuglevel(1)
                server.sendmail(email_config.email["from"], email_config.email["to"].split(" ,"), msg.as_string())
                server.quit()
            except Exception as e:
                logging.error(e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="smtp_sinkhole.py", usage="%(prog)s [host [port]]", description="SMTP Sinkhole")
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", type=int, default=1025)
    parser.add_argument("--dir", default=None, help="Directory used to dump emails.")
    parser.add_argument("--forward", action="store_true", default=False, help="Forward emails to specific email address")

    args = parser.parse_args()

    handler = CustomSMTPHandler()
    handler.mail_dir = args.dir
    handler.forward = args.forward
    server = aiosmtpd.controller.Controller(handler, hostname=args.host, port=args.port)
    server.start()
    input("Server started. Press Return to quit.")
    server.stop()
