# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_recondev
# Purpose:     Search Recon.dev for subdomains.
#
# Authors:     <bcoles@gmail.com>
#
# Created:     2020-08-14
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_recondev(GhostOsintPlugin):

    meta = {
        'name': "Recon.dev",
        'summary': "通过 Recon.dev 搜索子域名.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Passive DNS"],
        "dataSource": {
            "website": "https://recon.dev",
            'model': "FREE_AUTH_UNLIMITED",
            "references": ["https://recon.dev/api/docs"],
            "apiKeyInstructions": [
                "访问 https://recon.dev/",
                "注册一个账户",
                "访问 https://recon.dev/account 并使用提供的身份验证令牌",
            ],
            "description": "Recon.Dev 的任务是为黑客建立一个易于使用的平台，以便在整个公共互联网上轻松发现目标资产.",
        }
    }

    opts = {
        "api_key": "",
        "verify": True,
        "delay": 1
    }

    optdescs = {
        "api_key": "Recon.dev API 密钥.",
        "verify": "验证标识的域名是否仍解析为关联的指定IP地址.",
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
        return ["RAW_RIR_DATA", "INTERNET_NAME"]

    def queryDomain(self, qry):
        """Query a domain

        Args:
            qry (str): domain

        Returns:
            str: API response as JSON
        """

        headers = {
            "Accept": "application/json"
        }
        params = urllib.parse.urlencode({
            'key': self.opts['api_key'],
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        })
        res = self.GhostOsint.fetchUrl(
            f"https://recon.dev/api/search?{params}",
            headers=headers,
            timeout=30,
            useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def parseAPIResponse(self, res):
        # Future proofing - recon.dev does not implement rate limiting
        if res['code'] == '429':
            self.error("You are being rate-limited by Recon.dev")
            self.errorState = True
            return None

        if res['code'] == '500':
            self.error("Error during request from either an inproper domain/API key or you have used up all your API credits for the month")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from Recon.dev")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        # returns list of results; 'null' when no results; or dict when there's an error
        if not isinstance(data, list):
            self.error("Failed to retrieve content from Recon.dev")

            if isinstance(data, dict) and data.get('message'):
                self.debug(f"Failed to retrieve content from Recon.dev: {data.get('message')}")
                self.errorState = True
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

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        if eventName not in ["DOMAIN_NAME"]:
            return

        data = self.queryDomain(eventData)

        if data is None:
            self.debug(f"No information found for domain {eventData}")
            return

        evt = GhostOsintEvent('RAW_RIR_DATA', str(data), self.__name__, event)
        self.notifyListeners(evt)

        domains = []

        for result in data:
            raw_domains = result.get('rawDomains')
            if raw_domains:
                for domain in raw_domains:
                    domains.append(domain)

        for domain in set(domains):
            if self.checkForStop():
                return

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

# End of GO_recondev class
