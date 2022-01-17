# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_zoneh
# Purpose:      Checks if a domain or IP appears on the zone-h.org defacement
#               archive.
#
# Author:       steve@binarypool.com
#
# Created:     09/01/2014
# Copyright:   (c) Steve Micallef, 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_zoneh(GhostOsintPlugin):

    meta = {
        'name': "Zone-H 损坏检查",
        'summary': "检查 zone-h.org 'special defacements' RSS 提要上是否包含该主机名或域名.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://zone-h.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.zone-h.org/archive",
                "https://www.zone-h.org/archive/special=1"
            ],
            'favIcon': "https://zone-h.org/images/logo.gif",
            'logo': "https://zone-h.org/images/logo.gif",
            'description': "一旦损坏的网站提交到 Zone-H ，它将镜像到 Zone-H 服务器上. "
            "该网站随后由 Zone-H 工作人员主持，以检查损坏是否为伪造. "
            "有时，黑客自己会将被黑客攻击的页面提交到该网站.\n"
            "它是一个互联网安全门户，包含原始It安全新闻、数字战争新闻、地缘政治、专有和一般咨询、分析、论坛、研究. Zone-H 是最大的 WEB 入侵存档. "
            "它以多种语言出版.",
        }
    }

    # Default options
    opts = {
        'checkcohosts': True,
        'checkaffiliates': True
    }

    # Option descriptions
    optdescs = {
        'checkcohosts': "检查共同托管的网站?",
        'checkaffiliates': "检查关联公司?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS", "IPV6_ADDRESS",
                "AFFILIATE_INTERNET_NAME", "AFFILIATE_IPADDR", "AFFILIATE_IPV6_ADDRESS",
                "CO_HOSTED_SITE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DEFACED_INTERNET_NAME", "DEFACED_IPADDR",
                "DEFACED_AFFILIATE_INTERNET_NAME",
                "DEFACED_COHOST", "DEFACED_AFFILIATE_IPADDR"]

    def lookupItem(self, target, content):
        grps = re.findall(r"<title><\!\[CDATA\[(.[^\]]*)\]\]></title>\s+<link><\!\[CDATA\[(.[^\]]*)\]\]></link>", content)
        for m in grps:
            if target in m[0]:
                self.info("Found zoneh site: " + m[0])
                return m[0] + "\n<SFURL>" + m[1] + "</SFURL>"

        return False

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'CO_HOSTED_SITE' and not self.opts['checkcohosts']:
            return

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return

        if eventName == 'INTERNET_NAME':
            evtType = 'DEFACED_INTERNET_NAME'
        elif eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            evtType = 'DEFACED_IPADDR'
        elif eventName == 'CO_HOSTED_SITE':
            evtType = 'DEFACED_COHOST'
        elif eventName == 'AFFILIATE_INTERNET_NAME':
            evtType = 'DEFACED_AFFILIATE_INTERNET_NAME'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            evtType = 'DEFACED_AFFILIATE_IPADDR'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")

        if self.checkForStop():
            return

        url = "https://www.zone-h.org/rss/specialdefacements"
        content = self.GhostOsint.cacheGet("sfzoneh", 48)
        if content is None:
            data = self.GhostOsint.fetchUrl(url, useragent=self.opts['_useragent'])
            if data['content'] is None:
                self.error("Unable to fetch " + url)
                self.errorState = True
                return

            self.GhostOsint.cachePut("sfzoneh", data['content'])
            content = data['content']

        ret = self.lookupItem(eventData, content)
        if ret:
            evt = GhostOsintEvent(evtType, ret, self.__name__, event)
            self.notifyListeners(evt)

# End of GO_zoneh class
