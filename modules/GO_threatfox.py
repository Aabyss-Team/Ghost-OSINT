# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_threatfox
# Purpose:     Check if an IP address is malicious according to ThreatFox.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-09-20
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_threatfox(GhostOsintPlugin):

    meta = {
        'name': "ThreatFox",
        'summary': "根据 ThreatFox 检查IP地址是否为恶意地址.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://threatfox.abuse.ch/api/",
            ],
            'website': "https://threatfox.abuse.ch",
            'favIcon': 'https://threatfox.abuse.ch/favicon.ico',
            'logo': "https://threatfox.abuse.ch/images/threatfox_logo.png",
            'description': "ThreatFox 是一个来自 abuse.ch 的免费平台，目标是与信息安全社区、AV供应商和威胁情报提供商共享与恶意软件相关的危害指示器（IOCs）.",
        }
    }

    opts = {
        'checkaffiliates': True
    }

    optdescs = {
        'checkaffiliates': "检查关联企业?"
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
            "IP_ADDRESS",
            "AFFILIATE_IPADDR"
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
        ]

    def query(self, qry):
        """Query IOCs

        Args:
            qry (str): IP address

        Returns:
            str: API response data as JSON
        """
        params = {
            'query': 'search_ioc',
            'search_term': qry
        }

        headers = {
            "Accept": "application/json",
        }

        res = self.GhostOsint.fetchUrl(
            "https://threatfox-api.abuse.ch/api/v1/",
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout'],
            headers=headers,
            postData=json.dumps(params)
        )

        time.sleep(1)

        if res['content'] is None:
            return None

        if res['code'] == "429":
            self.error("You are being rate-limited by ThreatFox.")
            self.errorState = True
            return None

        if res['code'] != '200':
            self.error(f"Unexpected reply from ThreatFox: {res['code']}")
            self.errorState = True
            return None

        try:
            json_result = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from ThreatFox: {e}")
            return None

        query_status = json_result.get('query_status')

        if query_status == 'no_result':
            self.debug(f"No results from ThreatFox for: {qry}")
            return None

        if query_status != 'ok':
            self.debug(f"ThreatFox query failed: {query_status}")
            return None

        data = json_result.get('data')

        if not data:
            self.debug(f"No results from ThreatFox for: {qry}")
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if eventName not in self.watchedEvents():
            return

        self.results[eventData] = True

        if eventName == 'IP_ADDRESS':
            malicious_type = 'MALICIOUS_IPADDR'
            blacklist_type = 'BLACKLISTED_IPADDR'
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = 'MALICIOUS_AFFILIATE_IPADDR'
            blacklist_type = 'BLACKLISTED_AFFILIATE_IPADDR'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        data = self.query(eventData)

        if not data:
            return

        url = f"https://threatfox.abuse.ch/browse.php?search=ioc:{eventData}"
        text = f"ThreatFox [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = GhostOsintEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = GhostOsintEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of GO_threatfox class
