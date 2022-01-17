# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_abstractapi
# Purpose:     Search AbstractAPI for domain, phone and IP address information.
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     14/07/2019
# Copyright:   (c) Steve Micallef 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_abstractapi(GhostOsintPlugin):

    meta = {
        'name': "AbstractAPI",
        'summary': "通过AbstractAPI查找域名,电话或IP地址信息.",
        'flags': ["apikey"],
        'useCases': ["Passive", "Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://app.abstractapi.com/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://app.abstractapi.com/",
            ],
            'apiKeyInstructions': [
                "访问 https://app.abstractapi.com/users/signup",
                "注册免费账户",
                "访问 https://app.abstractapi.com/api/",
                "访问每个API页面并单击 'Try it out'",
                "你的API密钥将在 'This is your private API key, specific to this API.'",
            ],
            'favIcon': "https://app.abstractapi.com/favicon.ico",
            'logo': "https://app.abstractapi.com/logo192.png",
            'description': "Abstract 提供强大的 API 帮助你丰富用户体验和任何自动化流程."
        }
    }

    opts = {
        "companyenrichment_api_key": "",
        "phonevalidation_api_key": "",
        "ipgeolocation_api_key": "",
    }

    optdescs = {
        "companyenrichment_api_key": "AbstractAPI 企业 API key.",
        "phonevalidation_api_key": "AbstractAPI 电话验证 API key.",
        "ipgeolocation_api_key": "AbstractAPI IP地理定位 API key.",
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
        return ["DOMAIN_NAME", "PHONE_NUMBER", "IP_ADDRESS", "IPV6_ADDRESS"]

    def producedEvents(self):
        return ["COMPANY_NAME", "SOCIAL_MEDIA", "GEOINFO", "PHYSICAL_COORDINATES", "PROVIDER_TELCO", "RAW_RIR_DATA"]

    def parseApiResponse(self, res):
        if not res:
            return None

        if res['code'] == '429':
            self.error("You are being rate-limited by AbstractAPI.")
            return None

        if res['code'] == '401':
            self.error("Unauthorized. Invalid AbstractAPI API key.")
            self.errorState = True
            return None

        if res['code'] == '422':
            self.error("Usage quota reached. Insufficient API credit.")
            self.errorState = True
            return None

        if res['code'] == '500' or res['code'] == '503':
            self.error("Abstract API service is unavailable")
            self.errorState = True
            return None

        if res['code'] == '204':
            self.debug("No response data for target")
            return None

        if res['code'] != '200':
            self.error(f"Unexpected reply from AbstractAPI: {res['code']}")
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    def queryCompanyEnrichment(self, qry):
        """Enrich domain with company information.

        Args:
            qry (str): domain name

        Returns:
            dict: company information
        """

        api_key = self.opts['companyenrichment_api_key']
        if not api_key:
            return None

        params = urllib.parse.urlencode({
            'api_key': api_key,
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
        })

        res = self.GhostOsint.fetchUrl(
            f"https://companyenrichment.abstractapi.com/v1/?{params}",
            useragent=self.opts['_useragent']
        )

        time.sleep(1)

        if not res:
            self.debug("No response from AbstractAPI Company Enrichment API endpoint")
            return None

        return self.parseApiResponse(res)

    def queryPhoneValidation(self, qry):
        """Verify phone number and enrich with carrier and location information.

        Args:
            qry (str): phone number

        Returns:
            dict: phone number information
        """

        api_key = self.opts['phonevalidation_api_key']
        if not api_key:
            return None

        params = urllib.parse.urlencode({
            'api_key': api_key,
            'phone': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
        })

        res = self.GhostOsint.fetchUrl(
            f"https://phonevalidation.abstractapi.com/v1/?{params}",
            useragent=self.opts['_useragent']
        )

        time.sleep(1)

        if not res:
            self.debug("No response from AbstractAPI Phone Validation API endpoint")
            return None

        return self.parseApiResponse(res)

    def queryIpGeolocation(self, qry):
        """Enrich IP address with geolocation information.

        Args:
            qry (str): IPv4 address

        Returns:
            dict: location information
        """

        api_key = self.opts['ipgeolocation_api_key']
        if not api_key:
            return None

        params = urllib.parse.urlencode({
            'api_key': api_key,
            'ip_address': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
        })

        res = self.GhostOsint.fetchUrl(
            f"https://ipgeolocation.abstractapi.com/v1/?{params}",
            useragent=self.opts['_useragent']
        )

        time.sleep(1)

        if not res:
            self.debug("No response from AbstractAPI Phone Validation API endpoint")
            return None

        return self.parseApiResponse(res)

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if self.opts["companyenrichment_api_key"] == "" and self.opts["phonevalidation_api_key"] == "" and self.opts["ipgeolocation_api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set any API keys!"
            )
            self.errorState = True
            return

        if eventName not in self.watchedEvents():
            return

        if eventName == "DOMAIN_NAME":
            if self.opts["companyenrichment_api_key"] == "":
                self.info(
                    f"No API key set for Company Enrichment API endpoint. Ignoring {eventData}"
                )
                return

            data = self.queryCompanyEnrichment(eventData)

            if not data:
                return

            name = data.get('name')
            if not name:
                return

            if name == 'To Be Confirmed':
                return

            e = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
            self.notifyListeners(e)

            e = GhostOsintEvent("COMPANY_NAME", name, self.__name__, event)
            self.notifyListeners(e)

            linkedin_url = data.get('linkedin_url')
            if linkedin_url:
                if linkedin_url.startswith('linkedin.com'):
                    linkedin_url = f"https://{linkedin_url}"
                e = GhostOsintEvent("SOCIAL_MEDIA", f"LinkedIn (Company): <SFURL>{linkedin_url}</SFURL>", self.__name__, event)
                self.notifyListeners(e)

            locality = data.get('locality')
            country = data.get('country')
            geoinfo = ', '.join(
                filter(None, [locality, country])
            )

            if geoinfo:
                e = GhostOsintEvent("GEOINFO", geoinfo, self.__name__, event)
                self.notifyListeners(e)

        elif eventName == "PHONE_NUMBER":
            if self.opts["phonevalidation_api_key"] == "":
                self.info(
                    f"No API key set for Phone Validation API endpoint. Ignoring {eventData}"
                )
                return

            data = self.queryPhoneValidation(eventData)

            if not data:
                return

            valid = data.get('valid')
            if not valid:
                return

            e = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
            self.notifyListeners(e)

            carrier = data.get('carrier')
            if carrier:
                e = GhostOsintEvent("PROVIDER_TELCO", carrier, self.__name__, event)
                self.notifyListeners(e)

            location = data.get('location')
            country = data.get('country')
            country_name = None
            if country:
                country_name = country.get('name')

            geoinfo = ', '.join(
                filter(None, [location, country_name])
            )

            if geoinfo:
                e = GhostOsintEvent("GEOINFO", geoinfo, self.__name__, event)
                self.notifyListeners(e)

        elif eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            if self.opts["ipgeolocation_api_key"] == "":
                self.info(
                    f"No API key set for IP Geolocation API endpoint. Ignoring {eventData}"
                )
                return

            data = self.queryIpGeolocation(eventData)

            if not data:
                return

            e = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
            self.notifyListeners(e)

            geoinfo = ', '.join(
                [
                    _f for _f in [
                        data.get('city'),
                        data.get('region'),
                        data.get('postal_code'),
                        data.get('country'),
                        data.get('continent'),
                    ] if _f
                ]
            )

            if geoinfo:
                e = GhostOsintEvent("GEOINFO", geoinfo, self.__name__, event)
                self.notifyListeners(e)

            latitude = data.get('latitude')
            longitude = data.get('longitude')
            if latitude and longitude:
                e = GhostOsintEvent("PHYSICAL_COORDINATES", f"{latitude}, {longitude}", self.__name__, event)
                self.notifyListeners(e)

# End of GO_abstractapi class
