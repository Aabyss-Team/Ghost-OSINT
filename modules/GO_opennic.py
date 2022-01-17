# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_opnenic
# Purpose:     GhostOSINT plug-in for resolving host names on the OpenNIC
#              alternative DNS system.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-10-16
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import dns.resolver

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_opennic(GhostOsintPlugin):

    meta = {
        'name': "OpenNIC DNS",
        'summary': "解析 OpenNIC 备用 DNS 系统中的主机名.",
        'flags': [],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["DNS"],
        'dataSource': {
            'website': "https://www.opennic.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://wiki.opennic.org/",
                "https://servers.opennic.org",
            ],
            'description': "一个由运行备用DNS网络的爱好者组成的组织，还提供对不由ICANN管理的域的访问."
        }
    }

    opts = {
        'checkaffiliates': True,
    }

    optdescs = {
        'checkaffiliates': "检查关联企业?",
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "AFFILIATE_INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME_UNRESOLVED",
        ]

    def producedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
        ]

    def queryOpenNIC(self, qaddr):
        res = dns.resolver.Resolver()
        # https://servers.opennicproject.org/
        res.nameservers = [
            "185.121.177.177",
            "161.97.219.84",
            "163.172.168.171",
            "94.103.153.176",
            "207.192.71.13",
            "178.63.116.152",
            "209.141.36.19",
            "188.226.146.136",
            "198.98.51.33",
            "79.124.7.81",
            "144.76.103.143",
        ]

        try:
            return res.resolve(qaddr)
        except Exception:
            self.debug(f"Unable to resolve {qaddr}")

        return None

    def tlds(self):
        """Valid OpenNIC top-level domains.

        Returns:
            list: OpenNIC TLDs (and peer TLDs).
        """
        return [
            'bbs',
            'chan',
            'cyb',
            'dyn',
            'epic',
            'free',
            'geek',
            'glue',
            'gopher',
            'indy',
            'libre',
            'neo',
            'null',
            'o',
            'oss',
            'oz',
            'parody',
            'pirate',

            # Peers
            'bazar',
            'bit',
            'coin',
            'emc',
            'fur',
            'ku',
            'lib',
            'te',
            'ti',
            'uu',
        ]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventData.split('.')[-1] not in self.tlds():
            return

        affiliate = False

        if "AFFILIATE" in eventName:
            if not self.opts.get('checkaffiliates', False):
                return
            affiliate = True

        addrs = self.GhostOsint.normalizeDNS(self.queryOpenNIC(eventData))

        if not addrs:
            return

        self.debug(f"OpenNIC resolved {eventData} to addresses: {addrs}")

        for addr in set(addrs):
            if self.GhostOsint.validIP(addr):
                if affiliate and not self.getTarget().matches(addr, includeParents=True):
                    evt = GhostOsintEvent("AFFILIATE_IPADDR", addr, self.__name__, event)
                else:
                    evt = GhostOsintEvent("IP_ADDRESS", addr, self.__name__, event)

                self.notifyListeners(evt)
            elif self.GhostOsint.validIP6(addr):
                if affiliate and not self.getTarget().matches(addr, includeParents=True):
                    evt = GhostOsintEvent("AFFILIATE_IPV6_ADDRESS", addr, self.__name__, event)
                else:
                    evt = GhostOsintEvent("IPV6_ADDRESS", addr, self.__name__, event)

                self.notifyListeners(evt)
            else:
                continue

# End of GO_opennic class
