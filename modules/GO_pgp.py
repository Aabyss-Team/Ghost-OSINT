# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_pgp
# Purpose:      GhostOSINT plug-in for looking up received e-mails in PGP
#               key servers as well as finding e-mail addresses belonging to
#               your target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     17/02/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_pgp(GhostOsintPlugin):

    meta = {
        'name': "PGP 公钥服务器",
        'summary': "在 PGP 公钥服务器中查找电子邮件地址.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"]
    }

    results = None

    # Default options
    opts = {
        # options specific to this module
        'keyserver_search1': "https://pgp.key-server.io/pks/lookup?fingerprint=on&op=vindex&search=",
        'keyserver_fetch1': "https://pgp.key-server.io/pks/lookup?op=get&search=",
        'keyserver_search2': "http://the.earth.li:11371/pks/lookup?op=index&search=",
        'keyserver_fetch2': "http://the.earth.li:11371/pks/lookup?op=get&search="
    }

    # Option descriptions
    optdescs = {
        'keyserver_search1': "用于查找域名中电子邮件地址的 PGP 公钥服务器 Url 地址. 域名将被附加.",
        'keyserver_fetch1': "用于查找电子邮件地址公钥的PGP公钥服务器 Url 地址. 将附加电子邮件地址.",
        'keyserver_search2': "备份PGP公钥服务器 Url地址 以查找域中的电子邮件地址. 域名将被附加.",
        'keyserver_fetch2': "备份PGP公钥服务器 Url地址 以查找电子邮件地址的公钥. 将附加电子邮件地址."
    }

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['INTERNET_NAME', "EMAILADDR", "DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["EMAILADDR", "EMAILADDR_GENERIC", "AFFILIATE_EMAILADDR", "PGP_KEY"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Get e-mail addresses on this domain
        if eventName in ["DOMAIN_NAME", "INTERNET_NAME"]:
            res = self.GhostOsint.fetchUrl(self.opts['keyserver_search1'] + eventData,
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])

            if res['content'] is None or res['code'] == "503":
                res = self.GhostOsint.fetchUrl(self.opts['keyserver_search2'] + eventData,
                                       timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])

            if res['content'] is not None and res['code'] != "503":
                emails = self.GhostOsint.parseEmails(res['content'])
                for email in emails:
                    if email.split("@")[0] in self.opts['_genericusers'].split(","):
                        evttype = "EMAILADDR_GENERIC"
                    else:
                        evttype = "EMAILADDR"

                    mailDom = email.lower().split('@')[1]
                    if not self.getTarget().matches(mailDom):
                        evttype = "AFFILIATE_EMAILADDR"

                    self.info("Found e-mail address: " + email)
                    evt = GhostOsintEvent(evttype, email, self.__name__, event)
                    self.notifyListeners(evt)

        if eventName == "EMAILADDR":
            res = self.GhostOsint.fetchUrl(self.opts['keyserver_fetch1'] + eventData,
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])

            if res['content'] is None or res['code'] == "503":
                res = self.GhostOsint.fetchUrl(self.opts['keyserver_fetch2'] + eventData,
                                       timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])

            if res['content'] is not None and res['code'] != "503":
                pat = re.compile("(-----BEGIN.*END.*BLOCK-----)", re.MULTILINE | re.DOTALL)
                matches = re.findall(pat, str(res['content']))
                for match in matches:
                    self.debug("Found public key: " + match)
                    if len(match) < 300:
                        self.debug("Likely invalid public key.")
                        continue

                    evt = GhostOsintEvent("PGP_KEY", match, self.__name__, event)
                    self.notifyListeners(evt)

# End of GO_pgp class
