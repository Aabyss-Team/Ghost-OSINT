# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_neutrinoapi
# Purpose:     GhostOSINT plug-in to search NeutrinoAPI for IP address info,
#              check IP address reputation, and search for phone location.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-11-30
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_neutrinoapi(GhostOsintPlugin):

    meta = {
        'name': "NeutrinoAPI",
        'summary': "通过 NeutrinoAPI 搜索电话位置信息、IP地址信息和主机的信誉度.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.neutrinoapi.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://www.neutrinoapi.com/api/api-basics/",
                "https://www.neutrinoapi.com/api/phone-validate/",
                "https://www.neutrinoapi.com/api/ip-info/",
                "https://www.neutrinoapi.com/api/ip-blocklist/",
                "https://www.neutrinoapi.com/api/host-reputation/",
            ],
            'apiKeyInstructions': [
                "访问 https://www.neutrinoapi.com/",
                "注册一个免费账户",
                "点击 'My Account'",
                "API 密钥将在 'Master Key'"
            ],
            'favIcon': "https://www.neutrinoapi.com/favicon.png",
            'logo': "https://www.neutrinoapi.com/favicon.png",
            'description': "Neutrino API - 通用 API - 构建智能的应用程序."
        }
    }

    # Default options
    opts = {
        'user_id': '',
        'api_key': '',
        'timeout': 30
    }

    # Option descriptions
    optdescs = {
        'user_id': "NeutrinoAPI 用户 ID.",
        'api_key': "NeutrinoAPI API 密钥.",
        'timeout': "查询超时（秒）."
    }

    results = None
    errorState = False

    # Initialize module and module options
    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.__dataSource__ = "NeutrinoAPI"
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'IPV6_ADDRESS', 'PHONE_NUMBER']

    # What events this module produces
    def producedEvents(self):
        return [
            'RAW_RIR_DATA',
            'BLACKLISTED_IPADDR',
            'MALICIOUS_IPADDR',
            'PROXY_HOST',
            'VPN_HOST',
            'TOR_EXIT_NODE',
            'GEOINFO',
        ]

    # Query the phone-validate REST API
    # https://www.neutrinoapi.com/api/phone-validate/
    def queryPhoneValidate(self, qry):
        res = self.GhostOsint.fetchUrl(
            'https://neutrinoapi.com/phone-validate',
            postData={"output-format": "json", "number": qry, "user-id": self.opts['user_id'], "api-key": self.opts['api_key']},
            timeout=self.opts['timeout'],
            useragent=self.opts['_useragent']
        )

        return self.parseApiResponse(res)

    # Query the ip-info REST API
    # https://www.neutrinoapi.com/api/ip-info/
    def queryIpInfo(self, qry):
        res = self.GhostOsint.fetchUrl(
            "https://neutrinoapi.com/ip-info",
            postData={"output-format": "json", "ip": qry, "user-id": self.opts['user_id'], "api-key": self.opts['api_key']},
            timeout=self.opts['timeout'],
            useragent=self.opts['_useragent']
        )

        return self.parseApiResponse(res)

    # Query the ip-blocklist REST API
    # https://www.neutrinoapi.com/api/ip-blocklist/
    def queryIpBlocklist(self, qry):
        res = self.GhostOsint.fetchUrl(
            "https://neutrinoapi.com/ip-blocklist",
            postData={"output-format": "json", "ip": qry, "vpn-lookup": True, "user-id": self.opts['user_id'], "api-key": self.opts['api_key']},
            timeout=self.opts['timeout'],
            useragent=self.opts['_useragent']
        )

        return self.parseApiResponse(res)

    # Query the host-reputation REST API
    # https://www.neutrinoapi.com/api/host-reputation/
    def queryHostReputation(self, qry):
        res = self.GhostOsint.fetchUrl(
            "https://neutrinoapi.com/host-reputation",
            postData={"output-format": "json", "host": qry, "user-id": self.opts['user_id'], "api-key": self.opts['api_key']},
            timeout=self.opts['timeout'],
            useragent=self.opts['_useragent']
        )

        return self.parseApiResponse(res)

    # Parse API response
    def parseApiResponse(self, res):
        if res['code'] == "403":
            self.error("Authentication failed")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        if res['code'] == "400":
            if data.get('api-error-msg'):
                self.error("Error: " + data.get('api-error-msg'))
                if "EXCEED" in data.get('api-error-msg'):
                    self.errorState = True
                    return None
            else:
                self.error("Error: HTTP 400")
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if self.opts['api_key'] == "":
            self.error("You enabled GO_neutrinoapi but did not set an API key!")
            self.errorState = True
            return

        if self.opts['user_id'] == "":
            self.error("You enabled GO_neutrinoapi but did not set a user ID!")
            self.errorState = True
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventName == 'PHONE_NUMBER':
            data = self.queryPhoneValidate(eventData)

            if data is None:
                self.debug("No phone info results found for " + eventData)
            else:
                if data.get('location') is not None and data.get('country') is not None:
                    if data.get('location') == data.get('country'):
                        location = data.get('location')
                    else:
                        location = data.get('location') + ', ' + data.get('country')

                    evt = GhostOsintEvent("GEOINFO", location, self.__name__, event)
                    self.notifyListeners(evt)
                    evt = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
                    self.notifyListeners(evt)

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            data = self.queryIpInfo(eventData)

            if data is None:
                self.debug("No IP info results found for " + eventData)
            else:
                if data.get('city') is not None and data.get('region') is not None and data.get('country-code') is not None:
                    location = data.get('city') + ', ' + data.get('region') + ', ' + data.get('country-code')
                    evt = GhostOsintEvent("GEOINFO", location, self.__name__, event)
                    self.notifyListeners(evt)

            data = self.queryIpBlocklist(eventData)

            if data is None:
                self.debug("No IP blocklist results found for " + eventData)
            else:
                if data.get('is-listed'):
                    evt = GhostOsintEvent("MALICIOUS_IPADDR", f"NeutrinoAPI - IP Blocklist [{eventData}]", self.__name__, event)
                    self.notifyListeners(evt)
                    evt = GhostOsintEvent("BLACKLISTED_IPADDR", f"NeutrinoAPI - IP Blocklist [{eventData}]", self.__name__, event)
                    self.notifyListeners(evt)
                    evt = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
                    self.notifyListeners(evt)

                    if data.get('is-proxy'):
                        evt = GhostOsintEvent("PROXY_HOST", eventData, self.__name__, event)
                        self.notifyListeners(evt)

                    if data.get('is-vpn'):
                        evt = GhostOsintEvent("VPN_HOST", eventData, self.__name__, event)
                        self.notifyListeners(evt)

                    if data.get('is-tor'):
                        evt = GhostOsintEvent("TOR_EXIT_NODE", eventData, self.__name__, event)
                        self.notifyListeners(evt)

            data = self.queryHostReputation(eventData)

            if data is None:
                self.debug("No host reputation results found for " + eventData)
            else:
                if data.get('is-listed'):
                    evt = GhostOsintEvent("MALICIOUS_IPADDR", f"NeutrinoAPI - Host Reputation [{eventData}]", self.__name__, event)
                    self.notifyListeners(evt)
                    evt = GhostOsintEvent("BLACKLISTED_IPADDR", f"NeutrinoAPI - Host Reputation [{eventData}]", self.__name__, event)
                    self.notifyListeners(evt)
                    evt = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
                    self.notifyListeners(evt)

# End of GO_neutrinoapi class
