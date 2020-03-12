# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import subprocess
import hashlib
import urllib.request, urllib.parse, urllib.error
import random

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
import six

def sanitize_file(filename):
    normals = filename.lower().replace('\\', ' ').replace('.', ' ').split(' ')
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals[-3:]]
    return ' '.join(hashed_components)

def sanitize_reg(keyname):
    normals = keyname.lower().replace('\\', ' ').split(' ')
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals[-2:]]
    return ' '.join(hashed_components)

def sanitize_cmd(cmd):
    normals = cmd.lower().replace('"', '').replace('\\', ' ').replace('.', ' ').split(' ')
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals]
    return ' '.join(hashed_components)

def sanitize_generic(value):
    return hashlib.md5(value.lower()).hexdigest()[:8]

def sanitize_domain(domain):
    components = domain.lower().split('.')
    hashed_components = [hashlib.md5(comp).hexdigest()[:8] for comp in components]
    return ' '.join(hashed_components)

def sanitize_ip(ipaddr):
    components = ipaddr.split('.')
    class_c = components[:3]
    return hashlib.md5('.'.join(class_c)).hexdigest()[:8] + " " + hashlib.md5(ipaddr).hexdigest()[:8]

def sanitize_url(url):
    # normalize URL according to CIF specification
    uri = url
    if ":" in url:
        uri = url[url.index(':')+1:]
    uri = uri.strip("/")
    quoted = urllib.parse.quote(uri.encode('utf8')).lower()
    return hashlib.md5(quoted).hexdigest()[:8]

def mist_convert(results):
    """ Performs conversion of analysis results to MIST format """
    lines = []

    if results["target"]["category"] == "file":
        lines.append("# FILE")
        lines.append("# MD5: " + results["target"]["file"]["md5"])
        lines.append("# SHA1: " + results["target"]["file"]["sha1"])
        lines.append("# SHA256: " + results["target"]["file"]["sha256"])
    elif results["target"]["category"] == "url":
        lines.append("# URL")
        lines.append("# MD5: " + hashlib.md5(results["target"]["url"]).hexdigest())
        lines.append("# SHA1: " + hashlib.sha1(results["target"]["url"]).hexdigest())
        lines.append("# SHA256: " + hashlib.sha256(results["target"]["url"]).hexdigest())

    if "behavior" in results and "summary" in results["behavior"]:
        for entry in results["behavior"]["summary"]["files"]:
            lines.append("file access|" + sanitize_file(entry))
        for entry in results["behavior"]["summary"]["write_files"]:
            lines.append("file write|" + sanitize_file(entry))
        for entry in results["behavior"]["summary"]["delete_files"]:
            lines.append("file delete|" + sanitize_file(entry))
        for entry in results["behavior"]["summary"]["read_files"]:
            lines.append("file read|" + sanitize_file(entry))
        for entry in results["behavior"]["summary"]["keys"]:
            lines.append("reg access|" + sanitize_reg(entry))
        for entry in results["behavior"]["summary"]["read_keys"]:
            lines.append("reg read|" + sanitize_reg(entry))
        for entry in results["behavior"]["summary"]["write_keys"]:
            lines.append("reg write|" + sanitize_reg(entry))
        for entry in results["behavior"]["summary"]["delete_keys"]:
            lines.append("reg delete|" + sanitize_reg(entry))
        for entry in results["behavior"]["summary"]["executed_commands"]:
            lines.append("cmd exec|" + sanitize_cmd(entry))
        for entry in results["behavior"]["summary"]["resolved_apis"]:
            lines.append("api resolv|" + sanitize_generic(entry))
        for entry in results["behavior"]["summary"]["mutexes"]:
            lines.append("mutex access|" + sanitize_generic(entry))
        for entry in results["behavior"]["summary"]["created_services"]:
            lines.append("service create|" + sanitize_generic(entry))
        for entry in results["behavior"]["summary"]["started_services"]:
            lines.append("service start|" + sanitize_generic(entry))
    if "signatures" in results:
        for entry in results["signatures"]:
            if entry["name"] == "antivirus_virustotal":
                continue
            sigline = "sig " + entry["name"] + "|"
            notadded = False
            if entry["data"]:
                for res in entry["data"]:
                    for key, value in res.items():
                        if isinstance(value, str):
                            lowerval = value.lower()
                            if lowerval.startswith("hkey"):
                                lines.append(sigline + sanitize_reg(value))
                            elif lowerval.startswith("c:"):
                                lines.append(sigline + sanitize_file(value))
                            else:
                                lines.append(sigline + sanitize_generic(value))
                        else:
                            notadded = True
            else:
                notadded = True
            if notadded:
                lines.append(sigline)
    if "network" in results:
        hosts = results["network"].get("hosts")
        if hosts:
            for host in hosts:
                lines.append("net con|" + sanitize_generic(host["country_name"]) + " " + sanitize_ip(host["ip"]))
        domains = results["network"].get("domains")
        if domains:
            for domain in domains:
                lines.append("net dns|" + sanitize_domain(domain["domain"]))
        httpreqs = results["network"].get("http")
        if httpreqs:
            for req in httpreqs:
                lines.append("net http|" + sanitize_url(req["uri"]))

    if "dropped" in results:
        for dropped in results["dropped"]:
            lines.append("file drop|" + "%08x" % (int(dropped["size"]) & 0xfffffc00) + " " + sanitize_generic(dropped["type"]))

    if len(lines) <= 4:
        return ""

    return "\n".join(lines) + "\n"

class Malheur(Report):
    """ Performs classification on the generated MIST reports """

    def run(self, results):
        """Runs Malheur processing
        @return: Nothing.  Results of this processing are obtained at an arbitrary future time.
        """
        if results["target"]["category"] in ["pcap"]:
            return

        basedir = os.path.join(CUCKOO_ROOT, "storage", "malheur")
        cfgpath = os.path.join(CUCKOO_ROOT, "conf", "malheur.conf")
        reportsdir = os.path.join(basedir, "reports")
        task_id = str(results["info"]["id"])
        outputfile = os.path.join(basedir, "malheur.txt." + hashlib.md5(str(random.random())).hexdigest())
        try:
            os.makedirs(reportsdir)
        except:
            pass

        mist = mist_convert(results)
        if mist:
            with open(os.path.join(reportsdir, task_id + ".txt"), "w") as outfile:
                outfile.write(mist)

        # might need to prevent concurrent modifications to internal state of malheur by only allowing
        # one analysis to be running malheur at a time

        path, dirs, files = next(os.walk(reportsdir))
        try:
            cmdline = ["malheur", "-c", cfgpath, "-o", outputfile, "cluster", reportsdir]
            run = subprocess.Popen(cmdline, stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
            out, err = run.communicate()
            for line in err.splitlines():
                if line.startswith("Warning: Discarding empty feature vector"):
                    badfile = line.split("'")[1].split("'")[0]
                    os.remove(os.path.join(reportsdir, badfile))

            # replace previous classification state with new results atomically
            os.rename(outputfile, outputfile[:-33])

        except Exception as e:
            raise CuckooReportError("Failed to perform Malheur classification: %s" % e)
