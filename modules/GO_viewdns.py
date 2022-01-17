# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_viewdns
# Purpose:     Reverse Whois lookups using ViewDNS.info API.
#
# Author:      Steve Micallef
#
# Created:     08/09/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib.error
import urllib.parse
import urllib.request

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_viewdns(GhostOsintPlugin):

    meta = {
        'name': "ViewDNS.info",
        'summary': "使用 viewdns.inf o识别共同托管的网站并执行反向 WHOIS 查找.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://viewdns.info/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://viewdns.info/api/docs",
                "https://viewdns.info/api/"
            ],
            'apiKeyInstructions': [
                "访问 https://viewdns.info/api",
                "选择一个计划",
                "注册一个账户",
                "导航到 https://viewdns.info/api/dashboard/",
                "API 密钥将在 'API Key'"
            ],
            'favIcon': "https://viewdns.info/apple-touch-icon.png",
            'logo': "https://viewdns.info/images/viewdns_logo.gif",
            'description': "ViewDNS.info 允许网站管理员集成 ViewDNS 提供的工具. 以简单有效的方式将信息导入自己的网站.",
        }
    }

    opts = {
        "api_key": "",
        "verify": True,
        "maxcohost": 100
    }

    optdescs = {
        "api_key": "ViewDNS.info API 密钥.",
        "verify": "通过检查共享主机是否仍解析为共享IP地址来验证它们是否有效.",
        "maxcohost": "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的."
    }

    results = None
    errorState = False
    accum = list()
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.accum = list()
        self.cohostcount = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "EMAILADDR",
            "IP_ADDRESS",
            "PROVIDER_DNS"
        ]

    def producedEvents(self):
        return [
            'AFFILIATE_INTERNET_NAME',
            'AFFILIATE_DOMAIN_NAME',
            'CO_HOSTED_SITE'
        ]

    def query(self, qry, querytype, page=1):
        if querytype == "reverseip":
            attr = "host"
            pagesize = 10000
            responsekey = "domains"
        elif querytype == "reversens":
            attr = "ns"
            pagesize = 10000
            responsekey = "domains"
        elif querytype == "reversewhois":
            attr = "q"
            responsekey = "matches"
            pagesize = 1000
        else:
            return

        params = urllib.parse.urlencode({
            'apikey': self.opts['api_key'],
            attr: qry,
            'page': page,
            'output': 'json',
        })

        res = self.GhostOsint.fetchUrl(
            f"https://api.viewdns.info/{querytype}/?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent="GhostOSINT"
        )

        if res['code'] in ["400", "429", "500", "403"]:
            self.error("ViewDNS.info API key seems to have been rejected or you have exceeded usage limits.")
            self.errorState = True
            return

        if res['content'] is None:
            self.info(f"No ViewDNS.info data found for {qry}")
            return

        if res['content'] == 'Query limit reached for the supplied API key.':
            self.error("ViewDNS.info API usage limit exceeded.")
            self.errorState = True
            return

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from ViewDNS.info: {e}")
            return

        if not info.get("query"):
            self.error("Error querying ViewDNS.info. Could be unavailable right now.")
            self.errorState = True
            return

        response = info.get("response")

        if not response:
            return

        if response.get("error"):
            self.error(f"Error querying ViewDNS.info: {response.get('error')}")
            return

        if len(response.get(responsekey, list())) == pagesize:
            self.debug(f"Looping at ViewDNS page {page}")
            self.accum.extend(response.get(responsekey))
            self.query(qry, querytype, page + 1)

        # We are at the last or only page
        self.accum.extend(response.get(responsekey, []))

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if self.opts['api_key'] == "":
            self.error("You enabled GO_viewdns but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "EMAILADDR":
            ident = "reversewhois"
            valkey = "domain"
        elif eventName == "IP_ADDRESS":
            ident = "reverseip"
            valkey = "name"
        elif eventName == "PROVIDER_DNS":
            if not self.getTarget().matches(eventData):
                self.debug(f"DNS provider {eventData} not related to target, skipping")
                return
            ident = "reversens"
            valkey = "domain"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.accum = list()
        self.query(eventData, ident)
        rec = self.accum

        if not rec:
            return

        # Leave out registrar parking sites, and other highly used IPs
        if eventName in ["IP_ADDRESS", "IPV6_ADDRESS"] and len(rec) > self.opts['maxcohost']:
            self.debug(f"IP address {eventData} has {len(rec)} co-hosts; larger than {self.opts['maxcohost']}, skipping")
            return

        myres = list()

        for r in rec:
            h = r.get(valkey)

            if not h:
                continue

            if h.lower() in self.results:
                continue

            if h.lower() in myres:
                continue

            if h.lower() in ["demo1.com", "demo2.com", "demo3.com", "demo4.com", "demo5.com"]:
                continue

            myres.append(h.lower())

        for domain in set(myres):
            if not domain:
                continue

            if eventName == "EMAILADDR":
                e = GhostOsintEvent("AFFILIATE_INTERNET_NAME", domain, self.__name__, event)
                self.notifyListeners(e)

                if self.GhostOsint.isDomain(domain, self.opts['_internettlds']):
                    evt = GhostOsintEvent('AFFILIATE_DOMAIN_NAME', domain, self.__name__, event)
                    self.notifyListeners(evt)
            else:
                if self.cohostcount >= self.opts['maxcohost']:
                    continue

                if eventName in ["IP_ADDRESS", "IPV6_ADDRESS"] and self.opts['verify']:
                    if not self.GhostOsint.validateIP(domain, eventData):
                        self.debug(f"Host {domain} no longer resolves to IP address: {eventData}")
                        continue

                self.cohostcount += 1

                e = GhostOsintEvent("CO_HOSTED_SITE", domain, self.__name__, event)
                self.notifyListeners(e)

# End of GO_viewdns class
