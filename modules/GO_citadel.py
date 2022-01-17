# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_citadel
# Purpose:     GhostOSINT plug-in to search Leak-Lookup using their API,
#              for potential data breaches.
#
# Author:      sn <citadel.pw@protonmail.com>
#
# Created:     15/08/2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_citadel(GhostOsintPlugin):

    meta = {
        'name': "泄露信息查找",
        'summary': "查找 Leak-Lookup.com 数据库中的数据泄露.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://leak-lookup.com/",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://leak-lookup.com/api",
                "https://leak-lookup.com/databases"
            ],
            'apiKeyInstructions': [
                "访问 https://leak-lookup.com",
                "注册一个账户",
                "登录你的账户",
                "点击 'Account'",
                "点击 'API'",
                "API 密钥将在 'API Key'"
            ],
            'favIcon': "https://leak-lookup.com/favicon.png",
            'logo': "https://leak-lookup.com/favicon.png",
            'description': "Leak-Lookup 允许您搜索数以千计的数据泄露，以掌握可能已泄露的凭据，让您能够轻松主动地掌握最新的数据泄露.\n"
            "当创造者们意识到他们拥有大量的数据时，这些数据对于那些寻找客户端密码弱点的渗透测试人员以及那些关心他们的哪些凭据被泄露到了在野的人来说可能是非常有价值的.\n"
            "始终向前看，Leak-Lookup 将其所有利润投入到保护最新的数据泄露和泄漏转储，确保泄漏查找与历史数据一样成为凭据监控领域的领导者.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "timeout": 60
    }
    optdescs = {
        "api_key": "Leak-Lookup API 密钥.",
        "timeout": "自定义超时时间."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Leak-Lookup.com"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['EMAILADDR']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["EMAILADDR_COMPROMISED"]

    # Query email address
    # https://leak-lookup.com/api
    def queryEmail(self, email):
        apikey = self.opts['api_key']

        if not apikey:
            # Public API key
            apikey = "3edfb5603418f101926c64ca5dd0e409"

        params = {
            'query': email.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'type': 'email_address',
            'key': apikey
        }

        res = self.GhostOsint.fetchUrl("https://leak-lookup.com/api/search",
                               postData=urllib.parse.urlencode(params),
                               timeout=self.opts['timeout'],
                               useragent=self.opts['_useragent'])

        if res['code'] == "429":
            time.sleep(10)
            return self.queryEmail(email)

        if res['content'] is None:
            self.debug('No response from Leak-Lookup.com')
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.queryEmail(eventData)

        if data is None:
            return

        error = data.get('error')
        message = data.get('message')

        if error == 'true':
            self.error(f"Error encountered processing {eventData}: {message}")
            if "MISSING API" in message:
                self.errorState = True
                return
            return

        if not message:
            return

        for site in message:
            self.info(f"Found Leak-Lookup entry for {eventData}: {site}")
            evt = GhostOsintEvent("EMAILADDR_COMPROMISED", f"{eventData} [{site}]", self.__name__, event)
            self.notifyListeners(evt)

# End of GO_citadel class
