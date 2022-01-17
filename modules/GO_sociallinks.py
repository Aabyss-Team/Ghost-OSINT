# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_sociallinks
# Purpose:     ghostosint plugin to query SocialLinks.io to gather intelligence
#              from social media platforms and dark web.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     20/02/2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_sociallinks(GhostOsintPlugin):

    meta = {
        'name': "Social Links",
        'summary': "通过查询 SocialLinks.io 以从社交媒体平台和暗网收集情报.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://sociallinks.io/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://docs.osint.rest/"
            ],
            'apiKeyInstructions': [
                "访问 https://sociallinks.io/",
                "注册一个账户",
            ],
            'favIcon': "https://static.tildacdn.com/tild6563-6633-4533-b362-663333656461/favicon.ico",
            'logo': "https://static.tildacdn.com/tild3935-6136-4330-b561-643034663032/LogoSL.svg",
            'description': "Social Links 为世界领先的调查和执法机构使用的OSINT方法提供工具.",
        }
    }

    # Default options
    opts = {
        'api_key': '',
    }

    # Option descriptions
    optdescs = {
        'api_key': "Social Links API 密钥",
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "USERNAME",
            "EMAILADDR",
            "PHONE_NUMBER"
        ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [
            "GEOINFO",
            "SOCIAL_MEDIA",
            "HUMAN_NAME",
            "JOB_TITLE",
            "COMPANY_NAME",
            "PHONE_NUMBER",
            "ACCOUNT_EXTERNAL_OWNED",
            "RAW_RIR_DATA"
        ]

    def query(self, queryString):
        headers = {
            'Accept': "application/json",
            'Authorization': self.opts['api_key']
        }

        res = self.GhostOsint.fetchUrl(
            queryString,
            headers=headers,
            timeout=60,
            useragent=self.opts['_useragent']
        )

        if res['code'] == '429':
            self.error("You are being rate-limited by Social Links")
            self.errorState = True
            return None

        if res['code'] == '404':
            self.error("API Endpoint not found")
            self.errorState = True
            return None

        if res['code'] != "200":
            self.error("No search results from Social Links")
            return None

        if res['content'] is None:
            return None
        return json.loads(res['content'])

    def queryTelegram(self, qry, eventName):
        if eventName == "PHONE_NUMBER":
            queryString = f"https://osint.rest/api/telegram/user_by_phone?query={qry}"
        elif eventName == "USERNAME":
            queryString = f"https://osint.rest/api/telegram/user_by_alias?query={qry}"

        return self.query(queryString)

    def queryFlickr(self, qry):
        queryString = f"https://osint.rest/api/flickr/email?email={qry}"

        return self.query(queryString)

    def querySkype(self, qry):
        queryString = f"https://osint.rest/api/skype/search/v2?query={qry}"

        return self.query(queryString)

    def queryLinkedin(self, qry):
        queryString = f"https://osint.rest/api/linkedin/lookup_by_email/v2?query={qry}"

        return self.query(queryString)

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled GO_sociallinks but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "PHONE_NUMBER":
            data = self.queryTelegram(eventData, eventName)
            if data is None:
                return

            resultSet = data.get('result')
            if resultSet:
                if resultSet.get('first_name') and resultSet.get('last_name'):
                    evt = GhostOsintEvent("HUMAN_NAME", f"{resultSet.get('first_name')} {resultSet.get('last_name')}", self.__name__, event)
                    self.notifyListeners(evt)
                if resultSet.get('username'):
                    evt = GhostOsintEvent("USERNAME", resultSet.get('username'), self.__name__, event)
                    self.notifyListeners(evt)

                evt = GhostOsintEvent('RAW_RIR_DATA', str(resultSet), self.__name__, event)
                self.notifyListeners(evt)

        elif eventName == "USERNAME":
            data = self.queryTelegram(eventData, eventName)
            if data is None:
                return

            resultSet = data.get('result')
            if resultSet:
                if resultSet.get('first_name') and resultSet.get('last_name'):
                    evt = GhostOsintEvent("HUMAN_NAME", f"{resultSet.get('first_name')} {resultSet.get('last_name')}", self.__name__, event)
                    self.notifyListeners(evt)
                if resultSet.get('phone_number'):
                    evt = GhostOsintEvent("PHONE_NUMBER", resultSet.get('phone_number'), self.__name__, event)
                    self.notifyListeners(evt)

                evt = GhostOsintEvent('RAW_RIR_DATA', str(resultSet), self.__name__, event)
                self.notifyListeners(evt)

        elif eventName == "EMAILADDR":
            failedModules = 0
            data = self.queryFlickr(eventData)
            humanNames = set()
            geoInfos = set()
            if data is None:
                failedModules += 1
            else:
                resultSet = data[0].get('entities')[0].get('data')
                if resultSet:
                    if resultSet.get('realname').get('_content'):
                        humanNames.add(resultSet.get('realname').get('_content'))
                    if resultSet.get('location').get('_content'):
                        geoInfos.add(resultSet.get('location').get('_content'))
                    if resultSet.get('profileurl').get('_content'):
                        evt = GhostOsintEvent("SOCIAL_MEDIA", f"Flickr: <SFURL>{resultSet.get('profileurl').get('_content')}</SFURL>", self.__name__, event)
                        self.notifyListeners(evt)

                    evt = GhostOsintEvent('RAW_RIR_DATA', str(resultSet), self.__name__, event)
                    self.notifyListeners(evt)

            data = self.querySkype(eventData)
            if data is None:
                failedModules += 1
            else:
                resultSet = data.get('result')
                if resultSet:
                    resultSet = data.get('result')[0].get('nodeProfileData')
                    if resultSet.get('name'):
                        humanNames.add(resultSet.get('name'))
                    if resultSet.get('skypeId'):
                        evt = GhostOsintEvent("ACCOUNT_EXTERNAL_OWNED", f"Skype [{resultSet.get('skypeId')}]", self.__name__, event)
                        self.notifyListeners(evt)
                        evt = GhostOsintEvent("USERNAME", resultSet.get('skypeId'), self.__name__, event)
                        self.notifyListeners(evt)
                    if resultSet.get('address'):
                        geoInfos.add(resultSet.get('address'))

                    evt = GhostOsintEvent('RAW_RIR_DATA', str(resultSet), self.__name__, event)
                    self.notifyListeners(evt)

            data = self.queryLinkedin(eventData)
            if data is None:
                failedModules += 1
            else:
                resultSet = data.get('result')
                if resultSet:
                    resultSet = data.get('result')[0]
                    if resultSet.get('displayName'):
                        humanNames.add(resultSet.get('displayName'))
                    if resultSet.get('location'):
                        geoInfos.add(resultSet.get('location'))
                    if resultSet.get('companyName'):
                        evt = GhostOsintEvent("COMPANY_NAME", resultSet.get('companyName'), self.__name__, event)
                        self.notifyListeners(evt)
                    if resultSet.get('headline'):
                        evt = GhostOsintEvent("JOB_TITLE", resultSet.get('headline'), self.__name__, event)
                        self.notifyListeners(evt)

                    evt = GhostOsintEvent("SOCIAL_MEDIA", f"LinkedIn: <SFURL>{resultSet.get('linkedInUrl')}</SFURL>", self.__name__, event)
                    self.notifyListeners(evt)

                    evt = GhostOsintEvent('RAW_RIR_DATA', str(resultSet), self.__name__, event)
                    self.notifyListeners(evt)

            for humanName in humanNames:
                evt = GhostOsintEvent("HUMAN_NAME", humanName, self.__name__, event)
                self.notifyListeners(evt)

            for geoInfo in geoInfos:
                evt = GhostOsintEvent("GEOINFO", geoInfo, self.__name__, event)
                self.notifyListeners(evt)

            if failedModules == 3:
                self.info(f"No data found for {eventData}")
                return

# End of GO_sociallinks class
