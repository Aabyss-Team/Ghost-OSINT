# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_botvrij
# Purpose:      Check if a domain is malicious according to botvrij.eu.
#
# Author:       steve@binarypool.com
#
# Created:     16/05/2020
# Copyright:   (c) Steve Micallef, 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_botvrij(GhostOsintPlugin):

    meta = {
        'name': "botvrij.eu",
        'summary': "根据 botvrij.eu 检查域名是否为恶意域名.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://botvrij.eu/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Botvrij.eu 提供不同的开源IOC集，您可以在安全设备中使用这些IOC来检测可能的恶意活动.\n"
                "这些信息包含网络信息（IP地址）、文件哈希、文件路径、域名和URL链接.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 18
    }

    optdescs = {
        'checkaffiliates': "检查关联公司?",
        'checkcohosts': "检查目标IP地址上共同托管的站点?",
        'cacheperiod': "之前缓存提取."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME",
            "CO_HOSTED_SITE",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_INTERNET_NAME",
            "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            "BLACKLISTED_COHOST",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST",
        ]

    def queryBlacklist(self, target):
        blacklist = self.retrieveBlacklist()

        if not blacklist:
            return False

        if target.lower() in blacklist:
            self.debug(f"Host name {target} found in botvrij.eu blacklist.")
            return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.GhostOsint.cacheGet('botvrij', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        res = self.GhostOsint.fetchUrl(
            "https://www.botvrij.eu/data/blocklist/blocklist_full.csv",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from botvrij.eu.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from botvrij.eu")
            self.errorState = True
            return None

        self.GhostOsint.cachePut("botvrij", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from botvrij.eu

        Returns:
            list: list of blacklisted host names
        """
        hosts = list()

        if not blacklist:
            return hosts

        for line in blacklist.split('\n'):
            if not line:
                continue
            if line.startswith('#'):
                continue
            host = line.strip().split(",")[0].lower()
            # Note: Validation with GhostOsint.validHost() is too slow to use here
            # if not self.GhostOsint.validHost(host, self.opts['_internettlds']):
            #    continue
            hosts.append(host)

        return hosts

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName == "INTERNET_NAME":
            malicious_type = "MALICIOUS_INTERNET_NAME"
            blacklist_type = "BLACKLISTED_INTERNET_NAME"
        elif eventName == "AFFILIATE_INTERNET_NAME":
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_INTERNET_NAME"
            blacklist_type = "BLACKLISTED_AFFILIATE_INTERNET_NAME"
        elif eventName == "CO_HOSTED_SITE":
            if not self.opts.get('checkcohosts', False):
                return
            malicious_type = "MALICIOUS_COHOST"
            blacklist_type = "BLACKLISTED_COHOST"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with botvrij.eu")

        if not self.queryBlacklist(eventData):
            return

        url = "https://www.botvrij.eu/data/blocklist/blocklist_full.csv"
        text = f"botvrij.eu Domain Blocklist [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = GhostOsintEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = GhostOsintEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of GO_botvrij class
