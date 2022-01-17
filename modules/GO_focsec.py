# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_focsec
# Purpose:     Look up IP address information from Focsec.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-10-09
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_focsec(GhostOsintPlugin):

    meta = {
        'name': "Focsec",
        'summary': "从 Focsec 中查找 IP地址信息.",
        'flags': ['apikey'],
        'useCases': ["Passive", "Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://focsec.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.focsec.com/#ip",
            ],
            "apiKeyInstructions": [
                "访问 https://focsec.com/signup",
                "注册一个账户",
                "访问 https://focsec.com/account/dashboard 并使用提供的 API 密钥",
            ],
            'favIcon': "https://focsec.com/static/favicon.png",
            'logo': "https://focsec.com/static/web/images/logo.png",
            'description': "我们的 API让 您知道用户的 IP地址 是否与VPN、代理、TOR或恶意机器人程序相关联."
            "通过及早检测可疑活动，将应用程序的安全性提升到一个新的水平."
        }
    }

    opts = {
        "api_key": "",
    }

    optdescs = {
        "api_key": "Focsec API 密钥.",
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
            "IP_ADDRESS",
            "IPV6_ADDRESS"
        ]

    def producedEvents(self):
        return [
            "RAW_RIR_DATA",
            "GEOINFO",
            "MALICIOUS_IPADDR",
            "PROXY_HOST",
            "VPN_HOST",
            "TOR_EXIT_NODE",
        ]

    def query(self, qry):
        """Retrieve IP address information from Focsec.

        Args:
            qry (str): IPv4/IPv6 address

        Returns:
            dict: JSON formatted results
        """

        params = urllib.parse.urlencode({
            'api_key': self.opts["api_key"],
        })

        res = self.GhostOsint.fetchUrl(
            f"https://api.focsec.com/v1/ip/{qry}?{params}",
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts['_useragent']
        )

        if not res:
            self.error("No response from Focsec.")
            return None

        if res['code'] == "400":
            self.error("Bad request.")
            self.errorState = True
            return None

        if res['code'] == "401":
            self.error("Unauthorized - Invalid API key.")
            self.errorState = True
            return None

        if res['code'] == "402":
            self.error("Unauthorized - Payment Required. Subscription or trial period expired.")
            self.errorState = True
            return None

        if res['code'] == "404":
            self.debug(f"No results for {qry}")
            return None

        # Future proofing - Focsec does not implement rate limiting
        if res['code'] == "429":
            self.error("You are being rate-limited by Focsec.")
            return None

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from Focsec.")
            return None

        if not res['content']:
            self.debug("No results from Focsec.")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        data = self.query(eventData)

        if not data:
            self.debug(f"Found no results for {eventData}")
            return

        e = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(e)

        is_bot = data.get('is_bot')
        if is_bot:
            e = GhostOsintEvent("MALICIOUS_IPADDR", f"Focsec [{eventData}]", self.__name__, event)
            self.notifyListeners(e)

        is_tor = data.get('is_tor')
        if is_tor:
            e = GhostOsintEvent("TOR_EXIT_NODE", eventData, self.__name__, event)
            self.notifyListeners(e)

        is_vpn = data.get('is_vpn')
        if is_vpn:
            e = GhostOsintEvent("VPN_HOST", eventData, self.__name__, event)
            self.notifyListeners(e)

        is_proxy = data.get('is_proxy')
        if is_proxy:
            e = GhostOsintEvent("PROXY_HOST", eventData, self.__name__, event)
            self.notifyListeners(e)

        location = ', '.join(
            filter(
                None,
                [
                    data.get('city'),
                    data.get('country'),
                ]
            )
        )

        if location:
            e = GhostOsintEvent("GEOINFO", location, self.__name__, event)
            self.notifyListeners(e)

# End of GO_focsec class
