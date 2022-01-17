# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_torexits
# Purpose:     Checks if an IP address or netblock appears on the TOR Metrics
#              exit node list.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_torexits(GhostOsintPlugin):

    meta = {
        'name': "TOR 出口节点",
        'summary': "检查 IP地址 或网段是否出现在 Tor 指标出口节点列表上.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Secondary Networks"],
        'dataSource': {
            'website': "https://metrics.torproject.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://metrics.torproject.org/rs.html#search/flag:exit",
            ],
            'favIcon': "https://metrics.torproject.org/images/favicon.ico",
            'logo': "https://metrics.torproject.org/images/tor-metrics-white@2x.png",
            'description': "中继搜索工具显示有关 Tor 网络中单个中继和网桥的数据."
        },
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 1,
        'checknetblocks': True,
    }

    optdescs = {
        'checkaffiliates': "检查关联企业?",
        'cacheperiod': "之前缓存数据提取.",
        'checknetblocks': "报告网段中是否发现任何恶意IP地址?",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "torproject.org"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
        ]

    def producedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "TOR_EXIT_NODE",
        ]

    def queryExitNodes(self, ip):
        exit_addresses = self.retrieveExitNodes()

        if not exit_addresses:
            self.errorState = True
            return False

        if ip in exit_addresses:
            self.debug(f"IP address {ip} found in TOR exit node list.")
            return True

        return False

    def retrieveExitNodes(self):
        exit_addresses = self.GhostOsint.cacheGet('torexitnodes', self.opts.get('cacheperiod', 1))

        if exit_addresses is not None:
            return self.parseExitNodes(exit_addresses)

        res = self.GhostOsint.fetchUrl(
            "https://onionoo.torproject.org/details?search=flag:exit",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from onionoo.torproject.org.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from onionoo.torproject.org.")
            self.errorState = True
            return None

        self.GhostOsint.cachePut("torexitnodes", res['content'])

        return self.parseExitNodes(res['content'])

    def parseExitNodes(self, data):
        """Extract exit node IP addresses from TOR relay search results

        Args:
            data (str): TOR relay search results

        Returns:
            list: list of TOR exit IP addresses
        """
        ips = list()

        if not data:
            return ips

        try:
            results = json.loads(data)
        except Exception as e:
            self.error(f"Error processing JSON response: {e}")
            return None

        relays = results.get('relays')

        if not relays:
            return ips

        for relay in relays:
            or_addresses = relay.get('or_addresses')

            if or_addresses:
                for ip in or_addresses:
                    # IPv6 addresses are wrapped in [] (For example: "[127.0.0.1]:443")
                    if ip.startswith("["):
                        ip = ip.split('[')[1].split(']')[0]
                        if self.GhostOsint.validIP6(ip):
                            ips.append(ip)
                    else:
                        ip = ip.split(':')[0]
                        if self.GhostOsint.validIP(ip):
                            ips.append(ip)

            # Exit addresses are only listed in the exit addreses array
            # if the address differs from the OR address.
            exit_addresses = relay.get('exit_addresses')

            if exit_addresses:
                for ip in exit_addresses:
                    if self.GhostOsint.validIP(ip) or self.GhostOsint.validIP6(ip):
                        ips.append(ip)

        return list(set(ips))

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

        if eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return

        if eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts.get('checknetblocks', False):
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

            self.results[addr] = True

            if not self.queryExitNodes(addr):
                continue

            # For netblocks, we need to create the associated IP address event first.
            if eventName == 'NETBLOCK_OWNER':
                pevent = GhostOsintEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            if eventName == 'NETBLOCKV6_OWNER':
                pevent = GhostOsintEvent("IPV6_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            self.debug(f"IP address {addr} found in TOR exit node list.")
            evt = GhostOsintEvent("TOR_EXIT_NODE", addr, self.__name__, pevent)
            self.notifyListeners(evt)

# End of GO_torexits class
