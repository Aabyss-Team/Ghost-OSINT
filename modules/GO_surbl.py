# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_surbl
# Purpose:     GhostOSINT plug-in to check whether IP addresses, netblocks, and
#              domains appear in the SURBL blacklist.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-10-17
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_surbl(GhostOsintPlugin):

    meta = {
        'name': "SURBL",
        'summary': "检查网段、IP地址或域名是否在 SURBL 黑名单中.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://www.surbl.org/",
            'model': "FREE_NOAUTH_UNLIMITED",  # 250,000 messages per day
            'references': [
                "http://www.surbl.org/lists",
                "http://www.surbl.org/guidelines",
            ],
            'logo': "http://www.surbl.org/images/logo.png",
            'description': "SURBLs 是在未经请求的消息中出现的网站列表. "
            "与大多数列表不同，SURBL 不是消息发送者的列表."
        }
    }

    opts = {
        'checkaffiliates': True,
        'checkcohosts': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    optdescs = {
        'checkaffiliates': "检查关联企业?",
        'checkcohosts': "检查目标 IP地址 上共同托管的站点?",
        'netblocklookup': "在目标的网段上查找所有 IP 地址，以查找同一目标子域或域上可能被列入黑名单的主机?",
        'maxnetblock': "如果查找网段，则为查找其中所有IP的最大网段的大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'subnetlookup': "查找目标子网上的所有IP地址是否在黑名单中?",
        'maxsubnet': "如果查询子网则设置子网最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.errorState = False
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            'NETBLOCK_OWNER',
            'NETBLOCK_MEMBER',
            'INTERNET_NAME',
            'AFFILIATE_INTERNET_NAME',
            'CO_HOSTED_SITE',
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "BLACKLISTED_INTERNET_NAME",
            "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            "BLACKLISTED_COHOST",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST",
        ]

    # Swap 1.2.3.4 to 4.3.2.1
    def reverseAddr(self, ipaddr):
        if not self.GhostOsint.validIP(ipaddr):
            self.debug(f"Invalid IPv4 address {ipaddr}")
            return None
        return '.'.join(reversed(ipaddr.split('.')))

    def query(self, qaddr):
        """Query SURBL DNS.

        Args:
            qaddr (str): Host name or IPv4 address.

        Returns:
            list: SURBL DNS entries
        """
        if self.GhostOsint.validIP(qaddr):
            lookup = self.reverseAddr(qaddr) + '.multi.surbl.org'
        else:
            lookup = f"{qaddr}.multi.surbl.org"

        self.debug(f"Checking SURBL blacklist: {lookup}")

        try:
            return self.GhostOsint.resolveHost(lookup)
        except Exception as e:
            self.debug(f"SURBL did not resolve {qaddr} / {lookup}: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventName == "AFFILIATE_IPADDR":
            if not self.opts.get('checkaffiliates', False):
                return
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

        addrs = list()
        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                addrs.append(str(addr))
        else:
            addrs.append(eventData)

        for addr in addrs:
            if self.checkForStop():
                return

            if self.errorState:
                return

            res = self.query(addr)

            self.results[addr] = True

            if not res:
                continue

            self.debug(f"{addr} found in SURBL DNS")

            for result in res:
                k = str(result)

                if not k.startswith('127.0.0.'):
                    continue

                if k == '127.0.0.1':
                    self.error('SURBL rejected lookup request.')
                    self.errorState = True
                    continue

                evt = GhostOsintEvent(blacklist_type, f"SURBL [{addr}]", self.__name__, event)
                self.notifyListeners(evt)

                evt = GhostOsintEvent(malicious_type, f"SURBL [{addr}]", self.__name__, event)
                self.notifyListeners(evt)

# End of GO_surbl class
