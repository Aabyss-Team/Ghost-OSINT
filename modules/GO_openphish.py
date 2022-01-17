# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_openphish
# Purpose:      Check if a host/domain is malicious according to OpenPhish.com.
#
# Author:       steve@binarypool.com
#
# Created:     28/06/2018
# Copyright:   (c) Steve Micallef, 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_openphish(GhostOsintPlugin):

    meta = {
        'name': "OpenPhish",
        'summary': "根据 OpenPhish.com 检查主机或域名是否为恶意的.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://openphish.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://openphish.com/faq.html",
                "https://openphish.com/feed.txt"
            ],
            'favIcon': "",
            'logo': "https://openphish.com/static/openphish_logo2.png",
            'description': "及时精确的相关威胁情报.\n"
            "OpenPhish 是一个完全自动化的独立网络钓鱼智能平台. "
            "它可以识别钓鱼网站并实时执行情报分析，无需人工干预，也无需使用任何外部资源，如黑名单.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 18
    }

    optdescs = {
        'checkaffiliates': "检查关联企业?",
        'checkcohosts': "检查目标 IP地址 上共同托管的站点?",
        'cacheperiod': "之前缓存数据提取."
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
            self.debug(f"Host name {target} found in OpenPhish blacklist.")
            return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.GhostOsint.cacheGet('openphish', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        res = self.GhostOsint.fetchUrl(
            "https://www.openphish.com/feed.txt",
            timeout=10,
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from OpenPhish.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from OpenPhish")
            self.errorState = True
            return None

        self.GhostOsint.cachePut("openphish", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from OpenPhish

        Returns:
            list: list of blacklisted host names
        """
        hosts = list()

        if not blacklist:
            return hosts

        for line in blacklist.split('\n'):
            if not line:
                continue
            if not line.startswith('http'):
                continue

            # Note: URL parsing and validation with GhostOsint.validHost() is too slow to use here
            url = line.strip().lower()
            if len(url.split("/")) < 3:
                continue
            host = url.split("/")[2]
            if not host:
                continue
            if "." not in host:
                continue
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

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with OpenPhish")

        if not self.queryBlacklist(eventData):
            return

        url = "https://www.openphish.com/feed.txt"
        text = f"OpenPhish [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = GhostOsintEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = GhostOsintEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of GO_openphish class
