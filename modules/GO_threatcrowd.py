# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_threatcrowd
# Purpose:      Query threatcrowd.org for identified IP addresses.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     21/11/2016
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_threatcrowd(GhostOsintPlugin):

    meta = {
        'name': "ThreatCrowd",
        'summary': "从 ThreatCrowd 获取有关目标的IP地址、域名和电子邮件地址的信息.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.threatcrowd.org",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://threatcrowd.blogspot.com/2015/03/tutorial.html"
            ],
            'favIcon': "https://www.threatcrowd.org/img/favicon-32x32.png",
            'logo': "https://www.threatcrowd.org/img/home.png",
            'description': "ThreatCrowd API允许你快速识别相关的基础设施和恶意软件.\n"
            "使用 ThreatCrowd API，你可以搜索域名、IP地址、电子邮件地址、文件哈希、防病毒检测.",
        }
    }

    # Default options
    opts = {
        "checkcohosts": True,
        "checkaffiliates": True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    # Option descriptions
    optdescs = {
        "checkcohosts": "检查共同托管的网站?",
        "checkaffiliates": "检查关联公司?",
        'netblocklookup': "在目标的网段上查找同一目标子域或域上可能存在的主机的所有IP地址?",
        'maxnetblock': "如果查找网段，则为查找其中所有IP的最大网段的大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'subnetlookup': "查找目标所属子网上的所有IP地址?",
        'maxsubnet': "如果查询子网则设置子网最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "INTERNET_NAME",
                "CO_HOSTED_SITE", "NETBLOCK_OWNER", "EMAILADDR",
                "NETBLOCK_MEMBER", "AFFILIATE_INTERNET_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME",
                "MALICIOUS_COHOST", "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_NETBLOCK",
                "MALICIOUS_SUBNET", "MALICIOUS_EMAILADDR"]

    def query(self, qry):
        url = None

        if self.GhostOsint.validIP(qry):
            url = "https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=" + qry

        if "@" in qry:
            url = "https://www.threatcrowd.org/searchApi/v2/email/report/?email=" + qry

        if not url:
            url = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" + qry

        res = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent="GhostOSINT")

        if res['content'] is None:
            self.info(f"No ThreatCrowd info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from ThreatCrowd: {e}")
            self.errorState = True

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return

        if eventName == 'CO_HOSTED_SITE' and not self.opts['checkcohosts']:
            return

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

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            if self.checkForStop():
                return

            info = self.query(addr)
            if info is None:
                continue
            if info.get('votes', 0) < 0:
                self.info("Found ThreatCrowd URL data for " + addr)
                if eventName in ["IP_ADDRESS"] or eventName.startswith("NETBLOCK_"):
                    evt = "MALICIOUS_IPADDR"

                if eventName == "AFFILIATE_IPADDR":
                    evt = "MALICIOUS_AFFILIATE_IPADDR"

                if eventName == "INTERNET_NAME":
                    evt = "MALICIOUS_INTERNET_NAME"

                if eventName == "AFFILIATE_INTERNET_NAME":
                    evt = "MALICIOUS_AFFILIATE_INTERNET_NAME"

                if eventName == "CO_HOSTED_SITE":
                    evt = "MALICIOUS_COHOST"

                if eventName == "EMAILADDR":
                    evt = "MALICIOUS_EMAILADDR"

                infourl = "<SFURL>" + info.get('permalink') + "</SFURL>"

                # Notify other modules of what you've found
                e = GhostOsintEvent(evt, "ThreatCrowd [" + addr + "]\n" + infourl, self.__name__, event)
                self.notifyListeners(e)

# End of GO_threatcrowd class
