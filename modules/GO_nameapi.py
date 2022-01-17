# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_nameapi
# Purpose:      ghostosint plugin to check if an email is
#               disposable using nameapi.org API.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     2020-10-02
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_nameapi(GhostOsintPlugin):

    meta = {
        'name': "NameAPI",
        'summary': "检查电子邮件是否是一次性的",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.nameapi.org/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://www.nameapi.org/en/developer/manuals/rest-web-services/53/web-services/disposable-email-address-detector/"
            ],
            'apiKeyInstructions': [
                "访问 https://nameapi.org",
                "点击 'Get API Key'",
                "注册一个免费账户",
                "API 密钥将会发送到你的电子邮件中"
            ],
            'favIcon': "https://www.nameapi.org/fileadmin/favicon.ico",
            'logo': "https://www.nameapi.org/fileadmin/templates/nameprofiler/images/name-api-logo.png",
            'description': "NameAPI DEA-Detector 检查电子邮件地址 "
            "针对一直的垃圾域名列表，如 mailinator.com .\n"
            "它将这些分类为一次性的，作为一种有时间限制的、基于网络的接收电子邮件的方式，例如，注册确认.",
        }
    }

    opts = {
        'api_key': ''
    }

    optdescs = {
        'api_key': "NameAPI 密钥"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "EMAILADDR"
        ]

    def producedEvents(self):
        return [
            "EMAILADDR_DISPOSABLE",
            "RAW_RIR_DATA"
        ]

    def queryEmailAddr(self, qry):
        res = self.GhostOsint.fetchUrl(
            f"http://api.nameapi.org/rest/v5.3/email/disposableemailaddressdetector?apiKey={self.opts['api_key']}&emailAddress={qry}",
            timeout=self.opts['_fetchtimeout'],
            useragent="GhostOSINT"
        )

        if res['content'] is None:
            self.info(f"No NameAPI info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from NameAPI: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        self.results[eventData] = True

        data = self.queryEmailAddr(eventData)

        if data is None:
            return

        isDisposable = data.get('disposable')

        if isDisposable == "YES":
            evt = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
            self.notifyListeners(evt)

            evt = GhostOsintEvent("EMAILADDR_DISPOSABLE", eventData, self.__name__, event)
            self.notifyListeners(evt)

# End of GO_nameapi class
