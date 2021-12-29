# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_abusix
# Purpose:     GhostOSINT plugin for looking up whether IPs/Netblocks/Domains
#              appear in the Abusix Mail Intelligence blacklist.
# -------------------------------------------------------------------------------

import ipaddress

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_abusix(GhostOsintPlugin):

    meta = {
        'name': "Abusix Mail 情报",
        'summary': "检查网段或IP地址是否在 Abusix 邮件智能黑名单中.",
        'flags': ['apikey'],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://abusix.org/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://abusix.com/products/abusix-mail-intelligence/",
                "https://docs.abusix.com/105726-setup-abusix-mail-intelligence/ami%2Fsetup%2Fexample-queries",
                "https://docs.abusix.com/105725-detailed-list-information/ami%2Freturn-codes",
            ],
            'apiKeyInstructions': [
                "访问 https://app.abusix.com/signup",
                "注册一个免费用户",
                "浏览到 'Account Settings' 页面",
                "API密钥将在 'Email protection' 页面上."
            ],
            'logo': "https://abusix.com/wp-content/uploads/2020/10/Footer_logo.png",
            'description': "Abusix 智能邮件是一套全新的区块列表(RBL/DNSBL) "
            "可将实时的威胁数据添加到现有的电子邮件保护中. "
            "被视为第一道防线的区块列表有助于防止垃圾邮件 "
            "和恶意软件等电子邮件的传播威胁到你的网络."
        }
    }

    opts = {
        'api_key': "",
        'checkaffiliates': True,
        'checkcohosts': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        'subnetlookup': True,
        'maxsubnet': 24,
        'maxv6subnet': 120,
    }

    optdescs = {
        'api_key': "Abusix 智能邮件 API 密钥.",
        'checkaffiliates': "应用检查企业?",
        'checkcohosts': "应用检查于目标IP地址上托管的站点?",
        'netblocklookup': "在被视为你的目标所有的网段上查找同一目标子域或域名上可能被列入黑名单的主机的所有IP?",
        'maxnetblock': "如果查询网段则设置网段最小的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxv6netblock': "如果查询IPV6网段则设置网段最小的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'subnetlookup': "查找目标子网上的所有IP地址是否在黑名单中?",
        'maxsubnet': "如果查询网段则设置网段最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxv6subnet': "如果查询IPV6网段则设置网段最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
    }

    results = None
    errorState = False

    checks = {
        "127.0.0.2": "black",
        "127.0.0.3": "black (composite/heuristic)",
        "127.0.0.4": "exploit / authbl",
        "127.0.0.5": "forged",
        "127.0.0.6": "backscatter",
        "127.0.0.11": "policy (generic rDNS)",
        "127.0.0.12": "policy (missing rDNS)",
        "127.0.0.100": "noip",
        "127.0.1.1": "dblack",
        "127.0.1.2": "dblack (Newly Observed Domain)",
        "127.0.1.3": "dblack (Unshortened)",
        "127.0.2.1": "white",
        "127.0.3.1": "shorthash",
        "127.0.3.2": "diskhash",
        "127.0.4.1": "btc-wallets",
        "127.0.5.1": "attachhash",
    }

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.errorState = False
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'IPV6_ADDRESS',
            'AFFILIATE_IPADDR',
            'AFFILIATE_IPV6_ADDRESS',
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
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

    def reverseIpAddress(self, ipaddr):
        if not self.GhostOsint.validIP(ipaddr):
            self.debug(f"Invalid IPv4 address {ipaddr}")
            return None
        return ipaddress.ip_address(ipaddr).reverse_pointer.replace('.in-addr.arpa', '')

    def reverseIp6Address(self, ipaddr):
        if not self.GhostOsint.validIP6(ipaddr):
            self.debug(f"Invalid IPv6 address {ipaddr}")
            return None
        return ipaddress.ip_address(ipaddr).reverse_pointer.replace('.ip6.arpa', '')

    def query(self, qaddr):
        """Query Abusix Mail Intelligence DNS.

        Args:
            qaddr (str): Host name or IPv4 address.

        Returns:
            list: Abusix DNS entries
        """
        if self.GhostOsint.validIP(qaddr):
            lookup = f"{self.reverseIpAddress(qaddr)}.{self.opts['api_key']}.combined.mail.abusix.zone"
        elif self.GhostOsint.validIP6(qaddr):
            lookup = f"{self.reverseIp6Address(qaddr)}.{self.opts['api_key']}.combined.mail.abusix.zone"
        else:
            lookup = f"{qaddr}.{self.opts['api_key']}.combined.mail.abusix.zone"

        self.debug(f"Checking Abusix Mail Intelligence blacklist: {lookup}")

        try:
            return self.GhostOsint.resolveHost(lookup)
        except Exception as e:
            self.debug(f"Abusix Mail Intelligence did not resolve {qaddr} / {lookup}: {e}")

        return None

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

        if eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName in ['NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            if not self.opts['subnetlookup']:
                return

            if eventName == 'NETBLOCKV6_MEMBER':
                max_subnet = self.opts['maxv6subnet']
            else:
                max_subnet = self.opts['maxsubnet']

            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        elif eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts['netblocklookup']:
                return

            if eventName == 'NETBLOCKV6_OWNER':
                max_netblock = self.opts['maxv6netblock']
            else:
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
        if eventName.startswith("NETBLOCK"):
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

            self.debug(f"{addr} found in Abusix Mail Intelligence DNS")

            for result in res:
                k = str(result)

                if k not in self.checks:
                    if 'mail.abusix.zone' not in result:
                        # This is an error. The "checks" dict may need to be updated.
                        self.error(f"Abusix Mail Intelligence resolved address {addr} to unknown IP address {result} not found in Abusix Mail Intelligence list.")
                    continue

                text = f"Abusix Mail Intelligence - {self.checks[k]} [{addr}]\n<SFURL>https://lookup.abusix.com/search?q={addr}</SFURL>"

                evt = GhostOsintEvent(blacklist_type, text, self.__name__, event)
                self.notifyListeners(evt)

                evt = GhostOsintEvent(malicious_type, text, self.__name__, event)
                self.notifyListeners(evt)

# End of GO_abusix class
