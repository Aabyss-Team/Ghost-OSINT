# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_spamcop
# Purpose:      GhostOSINT plug-in for looking up whether IPs/Netblocks/Domains
#               appear in the spamcop block lists, indicating potential open-relays,
#               open proxies, malicious servers, vulnerable servers, etc.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/01/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_spamcop(GhostOsintPlugin):

    meta = {
        'name': "SpamCop",
        'summary': "检查网段或IP地址是否存储在 SpamCop 数据库中.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.spamcop.net/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.spamcop.net/help.shtml",
                "https://www.spamcop.net/bl.shtml",
                "https://www.spamcop.net/fom-serve/cache/291.html"
            ],
            'favIcon': "https://www.spamcop.net/images/favicon.ico",
            'logo': "https://www.spamcop.net/images/05logo.png",
            'description': "SpamCop 是报告垃圾邮件的首选服务. "
            "SpamCop 确定不需要的电子邮件的来源，并将其报告给相关的 Internet 服务提供商.",
        }
    }

    # Default options
    opts = {
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    optdescs = {
        'netblocklookup': "在目标的网段上查找所有 IP 地址，以查找同一目标子域或域上可能被列入黑名单的主机?",
        'maxnetblock': "如果查找网段，则为查找其中所有IP的最大网段的大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'subnetlookup': "查找目标子网上的所有IP地址是否在黑名单中?",
        'maxsubnet': "如果查询子网则设置子网最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)"
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            'NETBLOCK_OWNER',
            'NETBLOCK_MEMBER'
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

    # Swap 1.2.3.4 to 4.3.2.1
    def reverseAddr(self, ipaddr):
        if not self.GhostOsint.validIP(ipaddr):
            self.debug(f"Invalid IPv4 address {ipaddr}")
            return None
        return '.'.join(reversed(ipaddr.split('.')))

    def queryAddr(self, qaddr):
        """Query SpamCop DNS for an IPv4 address.

        Args:
            qaddr (str): IPv4 address.

        Returns:
            list: SpamCop DNS entries
        """
        if not self.GhostOsint.validIP(qaddr):
            self.debug(f"Invalid IPv4 address {qaddr}")
            return None

        try:
            lookup = self.reverseAddr(qaddr) + '.bl.spamcop.net'
            self.debug(f"Checking SpamCop blacklist: {lookup}")
            return self.GhostOsint.resolveHost(lookup)
        except Exception as e:
            self.debug(f"SpamCop did not resolve {qaddr} / {lookup}: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventName == "AFFILIATE_IPADDR":
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == "IP_ADDRESS":
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            max_subnet = self.opts['maxsubnet']
            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        addrs = list()
        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                addrs.append(str(addr))
        else:
            addrs.append(eventData)

        for addr in addrs:
            if self.checkForStop():
                return

            res = self.queryAddr(addr)

            self.results[addr] = True

            if not res:
                continue

            self.debug(f"{addr} found in SpamCop DNS")

            for result in res:
                k = str(result)
                if k != '127.0.0.2':
                    if not result.endswith('.bl.spamcop.net'):
                        # This is an error. SpamCop should only return 127.0.0.2 for matches.
                        self.error(f"SpamCop resolved address {addr} to unknown IP address {result}.")
                    continue

                url = f"https://www.spamcop.net/w3m?action=checkblock&ip={addr}"
                description = f"SpamCop Blacklist [{addr}]\n<SFURL>{url}</SFURL>"

                evt = GhostOsintEvent(blacklist_type, description, self.__name__, event)
                self.notifyListeners(evt)

                evt = GhostOsintEvent(malicious_type, description, self.__name__, event)
                self.notifyListeners(evt)

# End of GO_spamcop class
