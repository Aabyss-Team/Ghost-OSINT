# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_ipstack
# Purpose:      GhostOSINT plug-in to identify the Geo-location of IP addresses
#               identified by other modules using ipstack.com.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/08/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_ipstack(GhostOsintPlugin):

    meta = {
        'name': "ipstack",
        'summary': "通过 ipstack.com 查找标识的IP地址的物理位置.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://ipstack.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://ipstack.com/documentation",
                "https://ipstack.com/faq"
            ],
            'apiKeyInstructions': [
                "访问 https://ipstack.com/product",
                "点击 'Get Free API Key'",
                "点击 'Dashboard'",
                "API 密钥将在 'Your API Access Key'"
            ],
            'favIcon': "https://ipstack.com/ipstack_images/ipstack_logo.svg",
            'logo': "https://ipstack.com/ipstack_images/ipstack_logo.svg",
            'description': "通过IP地址定位和识别网站访问者.\n"
            "ipstack 提供全球领先的IP到地理位置API和全球IP数据库服务之一.",
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }
    optdescs = {
        "api_key": "Ipstack.com API 密钥."
    }
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["GEOINFO"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled GO_ipstack but did not set an API key!")
            self.errorState = True
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        res = self.GhostOsint.fetchUrl("http://api.ipstack.com/" + eventData + "?access_key=" + self.opts['api_key'],
                               timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
        if res['content'] is None:
            self.info("No GeoIP info found for " + eventData)

        try:
            hostip = json.loads(res['content'])
            if 'success' in hostip and hostip['success'] is False:
                self.error("Invalid ipstack.com API key or usage limits exceeded.")
                self.errorState = True
                return
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return

        geoinfo = hostip.get('country_name')
        if geoinfo:
            self.info(f"Found GeoIP for {eventData}: {geoinfo}")
            evt = GhostOsintEvent("GEOINFO", geoinfo, self.__name__, event)
            self.notifyListeners(evt)

# End of GO_ipstack class
