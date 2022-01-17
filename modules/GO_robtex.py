# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_robtex
# Purpose:      Searches Robtex.com for hosts sharing the same IP.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_robtex(GhostOsintPlugin):

    meta = {
        'name': "Robtex",
        'summary': "在 Robtex.com 上搜索共享相同IP地址的主机.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "https://www.robtex.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.robtex.com/api/"
            ],
            'favIcon': "https://www.robtex.com/favicon.ico",
            'logo': "https://www.robtex.com/favicon.ico",
            'description': "Robtex 用于IP号码、域名等的各种研究. Robtex使用各种来源收集有关IP号码、域名、主机名、自治系统、路由等的公共信息. "
            "然后，它将数据索引到一个大数据库中，并提供对数据的免费访问.",
        }
    }

    # Default options
    opts = {
        'verify': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        'cohostsamedomain': False,
        'maxcohost': 100,
        'subnetlookup': False,
        'maxsubnet': 24,
        'maxv6subnet': 120,
    }

    # Option descriptions
    optdescs = {
        'verify': "通过检查共享主机是否仍解析为共享IP地址来验证它们是否有效.",
        'netblocklookup': "在被目标的网段上查找所有IP地址，以查找同一目标在子域名或域名上可能的协作主机?",
        'maxnetblock': "如果查找网段，则为查找其中所有IP的最大网段的大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxv6netblock': "如果查找拥有的网段，则为查找其中所有IP的最大IPv6网段大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'cohostsamedomain': "将同一目标域上的托管站点视为共同托管?",
        'maxcohost': "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的.",
        'subnetlookup': "查找目标所属子网上的所有IP地址?",
        'maxsubnet': "如果查询子网则设置子网最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxv6subnet': "如果查找子网，则为用于查找其中所有IP的最大IPv6子网大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
    }

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.cohostcount = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
        ]

    # What events this module produces
    def producedEvents(self):
        return ["CO_HOSTED_SITE", "IP_ADDRESS", "IPV6_ADDRESS", "RAW_RIR_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.cohostcount > self.opts['maxcohost']:
            return

        if srcModuleName == "GO_robtex":
            self.debug(f"Ignoring {eventName}, from self.")
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts['netblocklookup']:
                return

            if eventName == 'NETBLOCKV6_OWNER':
                max_netblock = self.opts['maxv6netblock']
            else:
                max_netblock = self.opts['maxnetblock']

            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

        if eventName in ['NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            if not self.opts['subnetlookup']:
                return

            if eventName == 'NETBLOCKV6_MEMBER':
                max_subnet = self.opts['maxv6subnet']
            else:
                max_subnet = self.opts['maxsubnet']

            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

        qrylist = list()
        if eventName.startswith("NETBLOCK"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)
            self.results[eventData] = True

        retries = 3
        for ip in qrylist:
            retry = 0
            while retry < retries:
                if self.checkForStop():
                    return

                res = self.GhostOsint.fetchUrl("https://freeapi.robtex.com/ipquery/" + ip, timeout=self.opts['_fetchtimeout'])

                if res['code'] == "200":
                    break

                if res['code'] == "404":
                    continue

                if res['code'] == "429":
                    # Back off a little further
                    time.sleep(2)

                retry += 1

            if res['content'] is None:
                self.error("No reply from robtex API.")
                continue

            try:
                data = json.loads(res['content'])
            except Exception as e:
                self.error(f"Error parsing JSON from Robtex API: {e}")
                return

            if not data:
                continue

            status = data.get("status")

            if status and status == "ratelimited":
                self.error("You are being rate-limited by robtex API.")
                self.errorState = True
                continue

            evt = GhostOsintEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
            self.notifyListeners(evt)

            pas = data.get('pas')

            if not pas:
                self.info(f"No results from robtex API for {ip}")
                continue

            if not len(pas):
                continue

            for r in data.get('pas'):
                host = r.get('o')

                if not host:
                    continue

                if not self.opts['cohostsamedomain']:
                    if self.getTarget().matches(host, includeParents=True):
                        self.debug(f"Skipping {host} because it is on the same domain.")
                        continue

                if self.opts['verify'] and not self.GhostOsint.validateIP(host, ip):
                    self.debug(f"Host {host} no longer resolves to {ip}")
                    continue

                if eventName == "NETBLOCK_OWNER":
                    ipe = GhostOsintEvent("IP_ADDRESS", ip, self.__name__, event)
                    self.notifyListeners(ipe)
                    evt = GhostOsintEvent("CO_HOSTED_SITE", host, self.__name__, ipe)
                    self.notifyListeners(evt)
                elif eventName == "NETBLOCKV6_OWNER":
                    ipe = GhostOsintEvent("IPV6_ADDRESS", ip, self.__name__, event)
                    self.notifyListeners(ipe)
                    evt = GhostOsintEvent("CO_HOSTED_SITE", host, self.__name__, ipe)
                    self.notifyListeners(evt)
                else:
                    evt = GhostOsintEvent("CO_HOSTED_SITE", host, self.__name__, event)
                    self.notifyListeners(evt)

                self.cohostcount += 1

# End of GO_robtex class
