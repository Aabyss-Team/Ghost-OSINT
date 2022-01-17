# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_crobat_api
# Purpose:     Search Crobat API for subdomains.
#              https://www.onsecurity.co.uk/blog/how-i-made-rapid7s-project-sonar-searchable
#              https://github.com/cgboal/sonarsearch
#
# Authors:     <bcoles@gmail.com>
#
# Created:     2020-08-29
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_crobat_api(GhostOsintPlugin):

    meta = {
        'name': "Crobat API",
        'summary': "通过 Crobat API 搜索子域名.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "https://sonar.omnisint.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'logo': "https://sonar.omnisint.io/img/crobat.png",
            'description': "整个Rapid7 Sonar DNS数据集已编制索引，触手可及.",
        }
    }

    opts = {
        "verify": True,
        "max_pages": 10,
        "delay": 1
    }

    optdescs = {
        "verify": "DNS解析每个已识别的子域.",
        "max_pages": "提取结果最大页数.",
        "delay": "请求之间的延迟（秒）."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    def producedEvents(self):
        return ["RAW_RIR_DATA", "INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]

    def queryDomain(self, qry, page=0):
        headers = {
            "Accept": "application/json"
        }
        params = urllib.parse.urlencode({
            'page': page
        })
        domain = qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        res = self.GhostOsint.fetchUrl(
            f"https://sonar.omnisint.io/subdomains/{domain}?{params}",
            headers=headers,
            timeout=30,
            useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def parseAPIResponse(self, res):
        # Future proofing - Crobat API does not implement rate limiting
        if res['code'] == '429':
            self.error("You are being rate-limited by Crobat API")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from Crobat API")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        # returns "null" when page has no data
        if res['content'] == "null":
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        if not isinstance(data, list):
            self.error("Failed to retrieve content from Crobat API")
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName != "DOMAIN_NAME":
            return

        page = 0
        while page < self.opts['max_pages']:
            if self.checkForStop():
                return

            if self.errorState:
                return

            data = self.queryDomain(eventData, page)

            if not data:
                self.debug(f"No information found for domain {eventData} (page: {page})")
                return

            evt = GhostOsintEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(evt)

            page += 1

            for domain in set(data):
                if domain in self.results:
                    continue

                if not self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                    continue

                if self.opts['verify'] and not self.GhostOsint.resolveHost(domain) and not self.GhostOsint.resolveHost6(domain):
                    self.debug(f"Host {domain} could not be resolved")
                    evt = GhostOsintEvent("INTERNET_NAME_UNRESOLVED", domain, self.__name__, event)
                    self.notifyListeners(evt)
                else:
                    evt = GhostOsintEvent("INTERNET_NAME", domain, self.__name__, event)
                    self.notifyListeners(evt)

# End of GO_crobat_api class
