# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_emailrep
# Purpose:      Searches EmailRep.io for email address reputation.
#
# Author:      <bcoles[at]gmail[.]com>
#
# Created:     2019-08-07
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_emailrep(GhostOsintPlugin):

    meta = {
        'name': "EmailRep",
        'summary': "在 EmailRep.io 搜索电子邮件的信誉度.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://emailrep.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.emailrep.io/"
            ],
            'apiKeyInstructions': [
                "访问 https://emailrep.io/free",
                "请求一个免费的 API 密钥",
                "API密钥将在批准后发送到注册的电子邮件帐户"
            ],
            'favIcon': "https://emailrep.io/assets/img/favicon.png",
            'logo': "https://emailrep.io/assets/img/logo-light.png",
            'description': "阐明电子邮件背后的 \"信誉\".\n"
            "EmailRep 使用数百种因素来回答这些类型的问题，如域名年龄、流量排名、社交媒体网站、专业社交网站、"
            "个人关系、公共记录、可交付性、数据泄露、暗网网络凭据泄露、网络钓鱼电子邮件、威胁参与者电子邮件等.",
        }
    }

    opts = {
        'api_key': '',
    }

    optdescs = {
        'api_key': 'EmailRep API 密钥.',
    }

    results = None
    errorState = False
    errorWarned = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['EMAILADDR']

    def producedEvents(self):
        return ['RAW_RIR_DATA', 'EMAILADDR_COMPROMISED', 'MALICIOUS_EMAILADDR']

    # https://emailrep.io/docs/
    def query(self, qry):
        headers = {
            'Accept': "application/json"
        }

        if self.opts['api_key'] != '':
            headers['Key'] = self.opts['api_key']

        res = self.GhostOsint.fetchUrl(
            'https://emailrep.io/' + qry,
            headers=headers,
            useragent='GhostOSINT',
            timeout=self.opts['_fetchtimeout']
        )

        # Documentation does not indicate rate limit threshold (50 queries/day)
        time.sleep(1)

        if res['content'] is None:
            return None

        if res['code'] == '400':
            self.error('API error: Bad request')
            self.errorState = True
            return None

        if res['code'] == '401':
            self.error('API error: Invalid API key')
            self.errorState = True
            return None

        if res['code'] == '429':
            self.error('API error: Too Many Requests')
            self.errorState = True
            return None

        if res['code'] != '200':
            self.error('Unexpected reply from EmailRep.io: ' + res['code'])
            self.errorState = True
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

        if self.errorState:
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == '' and not self.errorWarned:
            self.error("Warning: You enabled GO_emailrep but did not set an API key! Queries will be rate limited.")
            self.errorWarned = True

        res = self.query(eventData)

        if res is None:
            return

        details = res.get('details')

        if not details:
            return

        credentials_leaked = details.get('credentials_leaked')
        if credentials_leaked:
            evt = GhostOsintEvent('EMAILADDR_COMPROMISED', eventData + " [Unknown]", self.__name__, event)
            self.notifyListeners(evt)

        malicious_activity = details.get('malicious_activity')
        if malicious_activity:
            evt = GhostOsintEvent('MALICIOUS_EMAILADDR', 'EmailRep [' + eventData + ']', self.__name__, event)
            self.notifyListeners(evt)

        if malicious_activity or credentials_leaked:
            evt = GhostOsintEvent('RAW_RIR_DATA', str(res), self.__name__, event)
            self.notifyListeners(evt)

# End of GO_emailrep class
