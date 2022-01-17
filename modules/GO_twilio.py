# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_twilio
# Purpose:      Extract data from phone numbers.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     14/06/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import base64
import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_twilio(GhostOsintPlugin):

    meta = {
        'name': "Twilio",
        'summary': "从 Twilio 获取有关电话号码的信息. 确保你在 Twilio 中安装了来电者姓名插件.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.twilio.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://www.twilio.com/docs/all",
                "https://www.twilio.com/blog/what-does-twilio-do"
            ],
            'apiKeyInstructions': [
                "访问 https://www.twilio.com",
                "注册一个免费账户",
                "导航到 https://www.twilio.com/console",
                "API 密钥将在 'Account SID' 和 'Auth Token'"
            ],
            'favIcon': "https://www.datasource.com/favicon.ico",
            'logo': "https://www.datasource.com/logo.gif",
            'description': "Twilio 是一家云通信平台，为加利福尼亚旧金山的服务公司. "
            "Twilio 允许软件开发人员使用其 WEB 服务 API 以编程方式拨打和接听电话、发送和接收文本消息以及执行其他通信功能.",
        }
    }

    opts = {
        'api_key_account_sid': '',
        'api_key_auth_token': ''
    }

    optdescs = {
        'api_key_account_sid': 'Twilio 账户 SID',
        'api_key_auth_token': 'Twilio Token'
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["PHONE_NUMBER"]

    def producedEvents(self):
        return ["COMPANY_NAME", "RAW_RIR_DATA"]

    # When querying third parties, it's best to have a dedicated function
    # to do so and avoid putting it in handleEvent()
    def queryPhoneNumber(self, phoneNumber):

        token = (base64.b64encode(self.opts['api_key_account_sid'].encode('utf8') + ":".encode('utf-8') + self.opts['api_key_auth_token'].encode('utf-8'))).decode('utf-8')

        headers = {
            'Accept': "application/json",
            'Authorization': "Basic " + token
        }

        res = self.GhostOsint.fetchUrl(
            f"https://lookups.twilio.com/v1/PhoneNumbers/{phoneNumber}?Type=caller-name",
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        if res['code'] == '400':
            self.error("Bad request.")
            return None

        if res['code'] == '404':
            self.debug("Phone number not found.")
            return None

        if res['code'] == '429':
            self.error("API usage limit reached.")
            return None

        if res['code'] == '503':
            self.error("Service unavailable.")
            return None

        if res['code'] != '200':
            self.error("Could not fetch data.")
            return None

        return res.get('content')

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Always check if the API key is set and complain if it isn't, then set
        # self.errorState to avoid this being a continual complaint during the scan.
        if self.opts['api_key_account_sid'] == "" or self.opts['api_key_auth_token'] == "":
            self.error("You enabled GO_twilio but did not set account sid/auth token")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        content = self.queryPhoneNumber(eventData)

        if content is None:
            return

        data = json.loads(content)

        evt = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

        callerName = data.get('caller_name')
        if callerName:
            callerName = callerName.get('caller_name')

        if callerName:
            evt = GhostOsintEvent("COMPANY_NAME", callerName, self.__name__, event)
            self.notifyListeners(evt)

# End of GO_twilio class
