# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_honeypot
# Purpose:     GhostOSINT plug-in for looking up whether IPs appear in the
#              ProjectHoneyPot.org database.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     16/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_honeypot(GhostOsintPlugin):

    meta = {
        'name': "Project Honey Pot",
        'summary': "在项目 Honey Pot 数据库中查询IP地址.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.projecthoneypot.org/",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://www.projecthoneypot.org/httpbl_api.php",
                "https://www.projecthoneypot.org/services_overview.php",
                "https://www.projecthoneypot.org/faq.php"
            ],
            'apiKeyInstructions': [
                "访问 https://www.projecthoneypot.org",
                "注册一个免费的账户",
                "导航到 https://www.projecthoneypot.org/httpbl_configure.php'",
                "请求一个 API 密钥",
                "API 密钥将在 'Your http:BL Access Key'"
            ],
            'favIcon': "https://www.projecthoneypot.org/favicon.ico",
            'logo': "https://www.projecthoneypot.org/images/php_logo.gif",
            'description': "Honey Pot 项目是第一个也是唯一一个用于识别垃圾邮件发送者和他们用来从你的网站上获取地址的垃圾邮件的分布式系统. "
            "使用 Honey Pot 项目系统，你可以自定义标记站点访问者的时间和IP地址. "
            "如果其中一个地址开始接收电子邮件，我们不仅可以知道这些邮件是垃圾邮件，还可以知道获取该地址的确切时间以及收集该地址的IP地址.",
        }
    }

    opts = {
        'api_key': "",
        'searchengine': False,
        'threatscore': 0,
        'timelimit': 30,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    optdescs = {
        'api_key': "ProjectHoneyPot.org API 密钥.",
        'searchengine': "包括搜索引擎认为的条目?",
        'threatscore': "最低威胁分值，0表示所有威胁，255表示最严重的威胁.",
        'timelimit': "条目的最大保留天数。255是最大值，0表示你什么也得不到.",
        'netblocklookup': "在目标的网段上查找同一目标子域或域上可能存在的主机的所有IP地址?",
        'maxnetblock': "如果查找网段，则为查找其中所有IP的最大网段的大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'subnetlookup': "查找目标所属网段上的所有IP?",
        'maxsubnet': "如果查询子网则设置子网最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)"
    }

    results = None
    errorState = False

    # Status codes according to:
    # http://www.projecthoneypot.org/httpbl_api.php
    statuses = {
        "0": "Search Engine",
        "1": "Suspicious",
        "2": "Harvester",
        "3": "Suspicious & Harvester",
        "4": "Comment Spammer",
        "5": "Suspicious & Comment Spammer",
        "6": "Harvester & Comment Spammer",
        "7": "Suspicious & Harvester & Comment Spammer",
        "8": "Unknown (8)",
        "9": "Unknown (9)",
        "10": "Unknown (10)"
    }

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "AFFILIATE_IPADDR",
            "NETBLOCK_OWNER",
            "NETBLOCK_MEMBER",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_NETBLOCK",
            "BLACKLISTED_SUBNET",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
        ]

    # Swap 1.2.3.4 to 4.3.2.1
    def reverseAddr(self, ipaddr):
        return '.'.join(reversed(ipaddr.split('.')))

    # Returns text about the IP status returned from DNS
    def parseDNS(self, addr):
        bits = addr.split(".")
        if int(bits[1]) > self.opts['timelimit']:
            return None

        if int(bits[2]) < self.opts['threatscore']:
            return None

        if int(bits[3]) == 0 and self.opts['searchengine']:
            return None

        return f"{self.statuses[bits[3]]}\nLast Activity: {bits[1]} days ago\nThreat Level: {bits[2]}"

    def queryAddr(self, qaddr, parentEvent):
        eventName = parentEvent.eventType

        text = None
        try:
            lookup = f"{self.opts['api_key']}.{self.reverseAddr(qaddr)}.dnsbl.httpbl.org"

            self.debug(f"Checking ProjectHoneyPot: {lookup}")
            addrs = self.GhostOsint.resolveHost(lookup)
            if not addrs:
                return

            self.debug(f"Addresses returned: {addrs}")

            for addr in addrs:
                text = self.parseDNS(addr)
                if text is not None:
                    break
        except Exception as e:
            self.debug(f"ProjectHoneyPot did not resolve {qaddr} / {lookup}: {e}")

        if not text:
            return

        if eventName == "AFFILIATE_IPADDR":
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == "IP_ADDRESS":
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == "NETBLOCK_OWNER":
            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        elif eventName == "NETBLOCK_MEMBER":
            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        url = f"https://www.projecthoneypot.org/ip_{qaddr}"

        evt = GhostOsintEvent(malicious_type, f"ProjectHoneyPot ({qaddr}): {text}\n<SFURL>{url}</SFURL>", self.__name__, parentEvent)
        self.notifyListeners(evt)

        evt = GhostOsintEvent(blacklist_type, f"ProjectHoneyPot ({qaddr}): {text}\n<SFURL>{url}</SFURL>", self.__name__, parentEvent)
        self.notifyListeners(evt)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if not self.opts['api_key']:
            self.error(f"You enabled {self.__class__.__name__} but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            max_subnet = self.opts['maxsubnet']
            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                if self.checkForStop():
                    return
                self.queryAddr(str(addr), event)
        else:
            self.queryAddr(eventData, event)

# End of GO_honeypot class
