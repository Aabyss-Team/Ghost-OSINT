# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_shodan
# Purpose:     Search Shodan for information related to the target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     19/03/2014
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_shodan(GhostOsintPlugin):

    meta = {
        'name': "SHODAN",
        'summary': "从 SHODAN 获取有关IP地址的信息.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.shodan.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://developer.shodan.io/api",
                "https://developer.shodan.io/apps"
            ],
            'apiKeyInstructions': [
                "访问 https://shodan.io",
                "注册一个免费账户",
                "导航到 https://account.shodan.io/",
                "API 密钥将在 'API Key'"
            ],
            'favIcon': "https://static.shodan.io/shodan/img/favicon.png",
            'logo': "https://static.shodan.io/developer/img/logo.png",
            'description': "Shodan 是世界上第一个互联网连接设备的搜索引擎.\n"
            "使用 Shodan 要了解您的哪些设备已连接到Internet、它们位于何处以及谁在使用它们."
            "跟踪网络上可直接从 Internet 访问的所有计算机。Shodan 让你了解你的数字足迹.",
        }
    }

    # Default options
    opts = {
        'api_key': "",
        'netblocklookup': True,
        'maxnetblock': 24
    }

    # Option descriptions
    optdescs = {
        "api_key": "SHODAN API 密钥.",
        'netblocklookup': "在目标的网段上查找同一目标子域或域上可能存在的主机的所有IP地址?",
        'maxnetblock': "如果查找网段，则为查找其中所有IP的最大网段的大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER", "DOMAIN_NAME", "WEB_ANALYTICS_ID"]

    # What events this module produces
    def producedEvents(self):
        return ["OPERATING_SYSTEM", "DEVICE_TYPE",
                "TCP_PORT_OPEN", "TCP_PORT_OPEN_BANNER",
                'RAW_RIR_DATA', 'GEOINFO',
                'VULNERABILITY_CVE_CRITICAL',
                'VULNERABILITY_CVE_HIGH', 'VULNERABILITY_CVE_MEDIUM',
                'VULNERABILITY_CVE_LOW', 'VULNERABILITY_GENERAL']

    def queryHost(self, qry):
        res = self.GhostOsint.fetchUrl(
            f"https://api.shodan.io/shodan/host/{qry}?key={self.opts['api_key']}",
            timeout=self.opts['_fetchtimeout'],
            useragent="GhostOSINT"
        )
        time.sleep(1)

        if res['content'] is None:
            self.info(f"No SHODAN info found for {qry}")
            return None

        try:
            r = json.loads(res['content'])
            if "error" in r:
                self.error(f"Error returned from SHODAN: {r['error']}")
                return None
            return r
        except Exception as e:
            self.error(f"Error processing JSON response from SHODAN: {e}")
            return None

        return None

    def searchHosts(self, qry):
        params = {
            'query': f"hostname:{qry}",
            'key': self.opts['api_key']
        }

        res = self.GhostOsint.fetchUrl(
            f"https://api.shodan.io/shodan/host/search?{urllib.parse.urlencode(params)}",
            timeout=self.opts['_fetchtimeout'],
            useragent="GhostOSINT"
        )
        time.sleep(1)
        if res['content'] is None:
            self.info(f"No SHODAN info found for {qry}")
            return None

        try:
            r = json.loads(res['content'])
            if "error" in r:
                self.error(f"Error returned from SHODAN: {r['error']}")
                return None
            return r
        except Exception as e:
            self.error(f"Error processing JSON response from SHODAN: {e}")
            return None

        return None

    def searchHtml(self, qry):
        params = {
            'query': 'http.html:"' + qry.encode('raw_unicode_escape').decode("ascii", errors='replace') + '"',
            'key': self.opts['api_key']
        }

        res = self.GhostOsint.fetchUrl(
            f"https://api.shodan.io/shodan/host/search?{urllib.parse.urlencode(params)}",
            timeout=self.opts['_fetchtimeout'],
            useragent="GhostOSINT"
        )
        time.sleep(1)
        if res['content'] is None:
            self.info(f"No SHODAN info found for {qry}")
            return None

        try:
            r = json.loads(res['content'])
            if "error" in r:
                self.error(f"Error returned from SHODAN: {r['error']}")
                return None
            if r.get('total', 0) == 0:
                self.info(f"No SHODAN info found for {qry}")
                return None
            return r
        except Exception as e:
            self.error(f"Error processing JSON response from SHODAN: {e}")
            return None

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled GO_shodan but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "DOMAIN_NAME":
            hosts = self.searchHosts(eventData)
            if hosts is None:
                return

            evt = GhostOsintEvent("RAW_RIR_DATA", str(hosts), self.__name__, event)
            self.notifyListeners(evt)

        if eventName == 'WEB_ANALYTICS_ID':
            try:
                network = eventData.split(": ")[0]
                analytics_id = eventData.split(": ")[1]
            except Exception as e:
                self.error(f"Unable to parse WEB_ANALYTICS_ID: {eventData} ({e})")
                return

            if network not in ['Google AdSense', 'Google Analytics', 'Google Site Verification']:
                self.debug(f"Skipping {eventData}, as not supported.")
                return

            rec = self.searchHtml(analytics_id)

            if rec is None:
                return

            evt = GhostOsintEvent("RAW_RIR_DATA", str(rec), self.__name__, event)
            self.notifyListeners(evt)
            return

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return
            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            rec = self.queryHost(addr)
            if rec is None:
                continue

            # For netblocks, we need to create the IP address event so that
            # the threat intel event is more meaningful.
            if eventName == 'NETBLOCK_OWNER':
                pevent = GhostOsintEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            evt = GhostOsintEvent("RAW_RIR_DATA", str(rec), self.__name__, pevent)
            self.notifyListeners(evt)

            if self.checkForStop():
                return

            if rec.get('os') is not None:
                evt = GhostOsintEvent("OPERATING_SYSTEM", f"{rec.get('os')} ({addr})", self.__name__, pevent)
                self.notifyListeners(evt)

            if rec.get('devtype') is not None:
                evt = GhostOsintEvent("DEVICE_TYPE", f"{rec.get('devtype')} ({addr})", self.__name__, pevent)
                self.notifyListeners(evt)

            if rec.get('country_name') is not None:
                location = ', '.join([_f for _f in [rec.get('city'), rec.get('country_name')] if _f])
                evt = GhostOsintEvent("GEOINFO", location, self.__name__, pevent)
                self.notifyListeners(evt)

            if 'data' not in rec:
                continue

            self.info(f"Found SHODAN data for {eventData}")
            ports = list()
            banners = list()
            asns = list()
            products = list()
            vulnlist = list()
            for r in rec['data']:
                port = str(r.get('port'))
                banner = r.get('banner')
                asn = r.get('asn')
                product = r.get('product')
                vulns = r.get('vulns')

                if port is not None:
                    cp = addr + ":" + port
                    if cp not in ports:
                        ports.append(cp)
                        evt = GhostOsintEvent("TCP_PORT_OPEN", cp, self.__name__, pevent)
                        self.notifyListeners(evt)

                if banner is not None:
                    if banner not in banners:
                        banners.append(banner)
                        evt = GhostOsintEvent("TCP_PORT_OPEN_BANNER", banner, self.__name__, pevent)
                        self.notifyListeners(evt)

                if product is not None:
                    if product not in products:
                        products.append(product)
                        evt = GhostOsintEvent("SOFTWARE_USED", product, self.__name__, pevent)
                        self.notifyListeners(evt)

                if asn is not None:
                    if asn not in asns:
                        asns.append(asn)
                        evt = GhostOsintEvent("BGP_AS_MEMBER", asn.replace("AS", ""), self.__name__, pevent)
                        self.notifyListeners(evt)

                if vulns is not None:
                    for vuln in vulns.keys():
                        if vuln not in vulnlist:
                            vulnlist.append(vuln)
                            etype, cvetext = self.GhostOsint.cveInfo(vuln)
                            evt = GhostOsintEvent(etype, cvetext, self.__name__, pevent)
                            self.notifyListeners(evt)

# End of GO_shodan class
