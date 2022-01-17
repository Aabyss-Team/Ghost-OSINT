# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_talosintel
# Purpose:      Check if a netblock or IP address is malicious according to
#               TalosIntelligence.
#
# Author:       steve@binarypool.com
#
# Created:     26/03/2019
# Copyright:   (c) Steve Micallef, 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_talosintel(GhostOsintPlugin):

    meta = {
        'name': "Talos Intelligence",
        'summary': "根据 TalosIntelligence 检查网段或IP地址是否为恶意地址.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://talosintelligence.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://talosintelligence.com/vulnerability_info",
                "https://talosintelligence.com/reputation"
            ],
            'favIcon': "https://talosintelligence.com/assets/favicons/favicon-49c9b25776778ff43873cf5ebde2e1ffcd0747ad1042ac5a5306cdde3ffca8cd.ico",
            'logo': "https://talosintelligence.com/assets/favicons/favicon-49c9b25776778ff43873cf5ebde2e1ffcd0747ad1042ac5a5306cdde3ffca8cd.ico",
            'description': "Cisco Talos 事件响应提供全套主动式和反应式服务，帮助你做好准备、做出响应并从违约中恢复. "
            "通过Talos IR，你可以直接访问Cisco提供的相同威胁情报和世界一流的应急响应能力，此外还有350多名威胁研究人员进行提问和分析. "
            "让我们的专家与你一起评估现有计划，制定新计划，并在你最需要时提供快速帮助.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    optdescs = {
        'checkaffiliates': "检查关联企业?",
        'cacheperiod': "之前缓存数据提取.",
        'checknetblocks': "报告网段中是否发现任何恶意IP地址?",
        'checksubnets': "检查在目标的同一子网内是否发现的任何恶意 IP 地址?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "AFFILIATE_IPADDR",
            "NETBLOCK_MEMBER",
            "NETBLOCK_OWNER"
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_SUBNET",
            "MALICIOUS_NETBLOCK",
        ]

    def queryBlacklist(self, target, targetType):
        blacklist = self.retrieveBlacklist()

        if not blacklist:
            return False

        if targetType == "ip":
            if target in blacklist:
                self.debug(f"IP address {target} found in Talos Intelligence blacklist.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in Talos Intelligence blacklist.")
                    return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.GhostOsint.cacheGet('talosintel', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        # https://talosintelligence.com/documents/ip-blacklist redirects to:
        # https://snort.org/downloads/ip-block-list
        res = self.GhostOsint.fetchUrl(
            "https://snort.org/downloads/ip-block-list",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from Talos Intelligence.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from Talos Intelligence")
            self.errorState = True
            return None

        self.GhostOsint.cachePut("talosintel", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from Talos Intelligence

        Returns:
            list: list of blacklisted IP addresses
        """
        ips = list()

        if not blacklist:
            return ips

        for ip in blacklist.split('\n'):
            ip = ip.strip()
            if ip.startswith('#'):
                continue
            if not self.GhostOsint.validIP(ip):
                continue
            ips.append(ip)

        return ips

    # Handle events sent to this module
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
            targetType = 'ip'
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with Talos Intelligence")

        if not self.queryBlacklist(eventData, targetType):
            return

        url = "https://snort.org/downloads/ip-block-list"
        text = f"Talos Intelligence [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = GhostOsintEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = GhostOsintEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of GO_talosintel class
