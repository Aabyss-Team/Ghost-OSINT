# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_blocklistde
# Purpose:      Check if a netblock or IP is malicious according to blocklist.de.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_blocklistde(GhostOsintPlugin):

    meta = {
        'name': "blocklist.de",
        'summary': "根据blocklist.de检查网段或IP地址是否是恶意的.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://www.blocklist.de/en/index.html",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "http://www.blocklist.de/en/api.html",
                "http://www.blocklist.de/en/rbldns.html",
                "http://www.blocklist.de/en/httpreports.html",
                "http://www.blocklist.de/en/export.html",
                "http://www.blocklist.de/en/delist.html?ip="
            ],
            'favIcon': "http://www.blocklist.de/templates/css/logo_web-size.jpg",
            'logo': "http://www.blocklist.de/templates/css/logo_web-size.jpg",
            'description': "www.blocklist.de 是为欺诈和滥用提供的免费自愿服务，其服务器经常通过SSH、邮件登录、FTP、Web服务器和其他服务受到攻击.\n"
            "任务是向受感染PC或服务器的各个滥用部门报告所有攻击，以确保责任提供商能够将感染情况告知其客户并使攻击者失效."
        }
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    optdescs = {
        'checkaffiliates': "检查关联公司?",
        'cacheperiod': "之前缓存数据提取.",
        'checknetblocks': "报告网段中是否发现任何恶意IP地址?",
        'checksubnets': "检查在目标的同一子网内是否发现任何恶意IP地址?"
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
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
        ]

    def queryBlacklist(self, target, targetType):
        blacklist = self.retrieveBlacklist()

        if not blacklist:
            return False

        if targetType == "ip":
            if target in blacklist:
                self.debug(f"IP address {target} found in blocklist.de blacklist.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in blocklist.de blacklist.")
                    return True

        return False

    def retrieveBlacklist(self):
        blacklist = self.GhostOsint.cacheGet('blocklistde', 24)

        if blacklist is not None:
            return self.parseBlacklist(blacklist)

        res = self.GhostOsint.fetchUrl(
            "https://lists.blocklist.de/lists/all.txt",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from blocklist.de.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from blocklist.de")
            self.errorState = True
            return None

        self.GhostOsint.cachePut("blocklistde", res['content'])

        return self.parseBlacklist(res['content'])

    def parseBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from blocklist.de

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
            if not self.GhostOsint.validIP(ip) and not self.GhostOsint.validIP6(ip):
                continue
            ips.append(ip)

        return ips

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

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            targetType = 'ip'
            malicious_type = 'MALICIOUS_IPADDR'
            blacklist_type = 'BLACKLISTED_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            malicious_type = 'MALICIOUS_AFFILIATE_IPADDR'
            blacklist_type = 'BLACKLISTED_AFFILIATE_IPADDR'
        elif eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            malicious_type = 'MALICIOUS_NETBLOCK'
            blacklist_type = 'BLACKLISTED_NETBLOCK'
        elif eventName in ['NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            malicious_type = 'MALICIOUS_SUBNET'
            blacklist_type = 'BLACKLISTED_SUBNET'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with blocklist.de")

        if self.queryBlacklist(eventData, targetType):
            # https://www.blocklist.de/en/search.html?ip=<ip>
            url = "https://lists.blocklist.de/lists/all.txt"
            text = f"blocklist.de [{eventData}]\n<SFURL>{url}</SFURL>"

            evt = GhostOsintEvent(malicious_type, text, self.__name__, event)
            self.notifyListeners(evt)

            evt = GhostOsintEvent(blacklist_type, text, self.__name__, event)
            self.notifyListeners(evt)

# End of GO_blocklistde class
