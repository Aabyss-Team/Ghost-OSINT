# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_googlemaps
# Purpose:      GhostOSINT plug-in to identify historical certificates for a domain
#               from googlemaps.sh, and from this identify hostnames.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     18/03/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_googlemaps(GhostOsintPlugin):

    meta = {
        'name': "Google 地图",
        'summary': "标识可能的物理地址和纬度/经度坐标.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://cloud.google.com/maps-platform/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://developers.google.com/maps/documentation/?_ga=2.135220017.1220421370.1587340370-900596925.1587340370"
            ],
            'apiKeyInstructions': [
                "访问 https://cloud.google.com/maps-platform/",
                "注册一个免费的账户",
                "点击 'Get Started'",
                "点击 'API'",
                "选择 API 类型",
                "导航到 https://console.cloud.google.com/apis/credentials",
                "点击 'Credentials'",
                "API 密钥将在 'API Keys'"
            ],
            'favIcon': "https://www.gstatic.com/devrel-devsite/prod/v2210deb8920cd4a55bd580441aa58e7853afc04b39a9d9ac4198e1cd7fbe04ef/cloud/images/favicons/onecloud/favicon.ico",
            'logo': "https://www.gstatic.com/devrel-devsite/prod/v2210deb8920cd4a55bd580441aa58e7853afc04b39a9d9ac4198e1cd7fbe04ef/cloud/images/cloud-logo.svg",
            'description': "探索真实世界的洞察力和身临其境的位置体验可以将您的业务带向何处.\n"
            "使用200多个国家和地区的可靠、全面的数据进行构建.\n"
            "已经在这里完成了.如果需要离线，则可以在我们的基础设施支持下自信地拆分规模.",
        }
    }

    opts = {
        "api_key": ""
    }
    optdescs = {
        "api_key": "Google Geocoding API 密钥."
    }
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['DOMAIN_NAME', 'PHYSICAL_ADDRESS']

    def producedEvents(self):
        return ["PHYSICAL_ADDRESS", "PHYSICAL_COORDINATES", "RAW_RIR_DATA"]

    def query(self, address):
        params = urllib.parse.urlencode({
            'key': self.opts['api_key'],
            'address': address.encode('raw_unicode_escape').decode("ascii", errors='replace')
        })

        res = self.GhostOsint.fetchUrl(
            f"https://maps.googleapis.com/maps/api/geocode/json?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.info(f"No location info found for {address}")
            return None

        return res

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

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

        res = self.query(eventData)

        if not res:
            self.debug(f"No information found for {eventData}")
            return

        evt = GhostOsintEvent(
            "RAW_RIR_DATA",
            res['content'],
            self.__name__,
            event
        )
        self.notifyListeners(evt)

        try:
            data = json.loads(res['content'])['results'][0]
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return

        if srcModuleName == "GO_googlemaps":
            return

        geometry = data.get('geometry')
        if geometry:
            location = data.get('location')
            if location:
                lat = location.get('lat')
                lng = location.get('lng')
                if lat and lng:
                    evt = GhostOsintEvent(
                        "PHYSICAL_COORDINATES",
                        f"{lat},{lng}",
                        self.__name__,
                        event
                    )
                    self.notifyListeners(evt)

        formatted_address = data.get('formatted_address')
        if formatted_address:
            evt = GhostOsintEvent(
                "PHYSICAL_ADDRESS",
                data['formatted_address'],
                self.__name__,
                event
            )
            self.notifyListeners(evt)

# End of GO_googlemaps class
