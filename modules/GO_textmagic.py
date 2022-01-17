# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_textmagic
# Purpose:      ghostosint module to retrieve phone number type
#               using TextMagic API
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     2020-10-05
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------
import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_textmagic(GhostOsintPlugin):

    meta = {
        "name": "TextMagic",
        "summary": "通过 TextMagic API 获取电话号码类型",
        'flags': ["apikey"],
        "useCases": ["Passive"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://www.textmagic.com/",
            "model": "FREE_AUTH_LIMITED",
            "references": [
                "https://docs.textmagic.com/"
            ],
            "apiKeyInstructions": [
                "访问 https://textmagic.com",
                "注册一个免费账户",
                "访问 https://my.textmagic.com/online/api/rest-api/keys",
                "点击 'Add new API Key'",
                "API 密钥将在 'The new API Key is'"
            ],
            "favIcon": "https://www.textmagic.com/wp-content/themes/textmagic-genesis/assets/app/images/favicon.png",
            "logo": "https://www.textmagic.com/wp-content/uploads/2015/04/logo.png",
            "description": "TextMagic 是一种商业短信服务，用于发送通知、警报、提醒、确认和短信营销活动.",
        },
    }

    opts = {
        "api_key_username": "",
        "api_key": "",
    }

    optdescs = {
        "api_key_username": "TextMagic API 用户名",
        "api_key": "TextMagic API 密钥",
    }

    errorState = False

    def setup(self, sfc, userOpts=None):
        if userOpts is None:
            userOpts = {}
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.opts.update(userOpts)

    def watchedEvents(self):
        return [
            "PHONE_NUMBER"
        ]

    def producedEvents(self):
        return [
            "PHONE_NUMBER_TYPE",
            "RAW_RIR_DATA"
        ]

    def handle_error_response(self, qry, res):
        try:
            error_info = json.loads(res["content"])
        except Exception:
            error_info = None
        if error_info:
            error_message = error_info.get("message")
        else:
            error_message = None
        if error_message:
            error_str = f", message {error_message}"
        else:
            error_str = ""
        self.error(f"Failed to get results for {qry}, code {res['code']}{error_str}")

    def queryPhoneNumber(self, qry):
        headers = {
            'X-TM-Username': self.opts['api_key_username'],
            'X-TM-Key': self.opts['api_key']
        }

        res = self.GhostOsint.fetchUrl(
            f"https://rest.textmagic.com/api/v2/lookups/{qry}",
            headers=headers,
            timeout=self.opts["_fetchtimeout"],
            useragent="GhostOSINT",
        )

        if res["code"] != "200":
            self.handle_error_response(qry, res)
            return None

        if res['content'] is None:
            self.info(f"No TextMagic info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from TextMagic: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "" or self.opts["api_key_username"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API Username/Key!"
            )
            self.errorState = True
            return

        self.results[eventData] = True

        data = self.queryPhoneNumber(event.data)

        if data is None:
            return

        phoneNumberType = data.get("type")
        if phoneNumberType is not None:
            evt = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
            self.notifyListeners(evt)

            evt = GhostOsintEvent("PHONE_NUMBER_TYPE", phoneNumberType, self.__name__, event)
            self.notifyListeners(evt)

# End of GO_textmagic class
