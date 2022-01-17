# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_cybercrimetracker
# Purpose:     Check if a host/domain or IP address is malicious according to cybercrime-tracker.net.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_cybercrimetracker(GhostOsintPlugin):

    meta = {
        'name': "CyberCrime-Tracker.net",
        'summary': "根据 CyberCrime-Tracker.net 检查主机和域名，以及 IP地址 是否是恶意的.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://cybercrime-tracker.net/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://cybercrime-tracker.net/tools.php",
                "https://cybercrime-tracker.net/about.php"
            ],
            'favIcon': "https://cybercrime-tracker.net/favicon.ico",
            'logo': "https://cybercrime-tracker.net/favicon.ico",
            'description': "CyberCrime 是一个C&C面板跟踪器, 换句话说, "
            "它列出了某些僵尸网络的管理接口.",
        }
    }

    # Default options
    opts = {
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 18
    }

    # Option descriptions
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
            "IP_ADDRESS",
            "AFFILIATE_INTERNET_NAME",
            "AFFILIATE_IPADDR",
            "CO_HOSTED_SITE"
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_INTERNET_NAME",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            "BLACKLISTED_COHOST",
            "MALICIOUS_IPADDR",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST"
        ]

    def queryBlacklist(self, target):
        blacklist = self.retrieveBlacklist()

        if not blacklist:
            return False

        if target.lower() in blacklist:
            self.debug(f"Host name {target} found in CyberCrime-Tracker.net blacklist.")
            return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.GhostOsint.cacheGet('cybercrime-tracker', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        res = self.GhostOsint.fetchUrl(
            "https://cybercrime-tracker.net/all.php",
            timeout=10,
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from CyberCrime-Tracker.net.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from CyberCrime-Tracker.net")
            self.errorState = True
            return None

        self.GhostOsint.cachePut("cybercrime-tracker", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from CyberCrime-Tracker.net

        Returns:
            list: list of blacklisted IP addresses and host names
        """
        hosts = list()

        if not blacklist:
            return hosts

        for line in blacklist.split('\n'):
            if not line:
                continue
            if line.startswith('#'):
                continue

            # Note: URL parsing and validation with GhostOsint.validHost() is too slow to use here
            host = line.split("/")[0]
            if not host:
                continue
            if "." not in host:
                continue
            hosts.append(host.split(':')[0])

        return hosts

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName == 'IP_ADDRESS':
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == "INTERNET_NAME":
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

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with CyberCrime-Tracker.net")

        if not self.queryBlacklist(eventData):
            return

        url = f"https://cybercrime-tracker.net/index.php?search={eventData}"
        text = f"CyberCrime-Tracker.net Malicious Submissions [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = GhostOsintEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = GhostOsintEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of GO_cybercrimetracker class
