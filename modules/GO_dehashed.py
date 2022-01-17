# -------------------------------------------------------------------------------
# Name:        GO_dehashed
# Purpose:     Gather breach data from Dehashed API.
#
# Author:      <krishnasis@hotmail.com>
#
# Created:     16-01-2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import base64
import json
import time

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_dehashed(GhostOsintPlugin):

    meta = {
        'name': "Dehashed",
        'summary': "通过 Dehashed API 搜索违规数据.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://www.dehashed.com/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://www.dehashed.com/docs"
            ],
            'apiKeyInstructions': [
                "访问 https://www.dehashed.com/register"
                "注册一个免费账户",
                "访问 https://www.dehashed.com/profile",
                "API 密钥将在 'API Key'",
            ],
            'favIcon': "https://www.dehashed.com/assets/img/favicon.ico",
            'logo': "https://www.dehashed.com/assets/img/logo.png",
            'description': "你已经妥协了吗? "
            "DeHashed 提供免费的 Deep-Web 扫描和凭证泄漏保护. "
            "为安全分析师、记者、安全公司和普通人创建的现代个人资产搜索引擎，帮助保护帐户并提供对受损资产的洞察. "
            "免费违约警报和违约通知.",
        }
    }

    # Default options
    opts = {
        'api_key_username': '',
        'api_key': '',
        'per_page': 10000,
        'max_pages': 2,
        'pause': 1
    }

    # Option descriptions
    optdescs = {
        'api_key_username': 'Dehashed 用户名.',
        'api_key': 'Dehashed API 密钥.',
        'per_page': '每页最大结果数.(最大: 10000)',
        'max_pages': '要提取的最大页数(最大: 10 pages)',
        'pause': '每个API调用之间等待的秒数.'
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "EMAILADDR"
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            'EMAILADDR',
            'EMAILADDR_COMPROMISED',
            'PASSWORD_COMPROMISED',
            'HASH_COMPROMISED',
            'RAW_RIR_DATA'
        ]

    # Query Dehashed
    def query(self, event, per_page, start):
        if event.eventType == "EMAILADDR":
            queryString = f"https://api.dehashed.com/search?query=email:\"{event.data}\"&page={start}&size={self.opts['per_page']}"
        if event.eventType == "DOMAIN_NAME":
            queryString = f"https://api.dehashed.com/search?query=email:\"@{event.data}\"&page={start}&size={self.opts['per_page']}"

        token = (base64.b64encode(self.opts['api_key_username'].encode('utf8') + ":".encode('utf-8') + self.opts['api_key'].encode('utf-8'))).decode('utf-8')
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Basic {token}'
        }

        res = self.GhostOsint.fetchUrl(queryString,
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'],
                               verify=True)

        time.sleep(self.opts['pause'])

        if res['code'] == "400":
            self.error("Too many requests were performed in a small amount of time. Please wait a bit before querying the API.")
            time.sleep(5)
            res = self.GhostOsint.fetchUrl(queryString, headers=headers, timeout=15, useragent=self.opts['_useragent'], verify=True)

        if res['code'] == "401":
            self.error("Invalid API credentials")
            self.errorState = True
            return None

        if res['code'] != "200":
            self.error("Unable to fetch data from Dehashed.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.debug('No response from Dehashed')
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

        if srcModuleName == self.__name__:
            return

        if eventData in self.results:
            return

        if self.errorState:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "" or self.opts['api_key_username'] == "":
            self.error("You enabled GO_dehashed but did not set an API key/API Key Username!")
            self.errorState = True
            return

        currentPage = 1
        maxPages = self.opts['max_pages']
        perPage = self.opts['per_page']

        while currentPage <= maxPages:
            if self.checkForStop():
                return

            if self.errorState:
                break

            data = self.query(event, perPage, currentPage)

            if not data:
                return

            breachResults = set()
            emailResults = set()

            if not data.get('entries'):
                return

            for row in data.get('entries'):
                email = row.get('email')
                password = row.get('password')
                passwordHash = row.get('hashed_password')
                leakSource = row.get('database_name', 'Unknown')

                if f"{email} [{leakSource}]" in breachResults:
                    continue

                breachResults.add(f"{email} [{leakSource}]")

                if eventName == "EMAILADDR":
                    if email == eventData:
                        evt = GhostOsintEvent('EMAILADDR_COMPROMISED', f"{email} [{leakSource}]", self.__name__, event)
                        self.notifyListeners(evt)

                        if password:
                            evt = GhostOsintEvent('PASSWORD_COMPROMISED', f"{email}:{password} [{leakSource}]", self.__name__, event)
                            self.notifyListeners(evt)

                        if passwordHash:
                            evt = GhostOsintEvent('HASH_COMPROMISED', f"{email}:{passwordHash} [{leakSource}]", self.__name__, event)
                            self.notifyListeners(evt)

                        evt = GhostOsintEvent('RAW_RIR_DATA', str(row), self.__name__, event)
                        self.notifyListeners(evt)

                if eventName == "DOMAIN_NAME":
                    pevent = GhostOsintEvent("EMAILADDR", email, self.__name__, event)
                    if email not in emailResults:
                        self.notifyListeners(pevent)
                        emailResults.add(email)

                    evt = GhostOsintEvent('EMAILADDR_COMPROMISED', f"{email} [{leakSource}]", self.__name__, pevent)
                    self.notifyListeners(evt)

                    if password:
                        evt = GhostOsintEvent('PASSWORD_COMPROMISED', f"{email}:{password} [{leakSource}]", self.__name__, pevent)
                        self.notifyListeners(evt)

                    if passwordHash:
                        evt = GhostOsintEvent('HASH_COMPROMISED', f"{email}:{passwordHash} [{leakSource}]", self.__name__, pevent)
                        self.notifyListeners(evt)

                    evt = GhostOsintEvent('RAW_RIR_DATA', str(row), self.__name__, pevent)
                    self.notifyListeners(evt)

            currentPage += 1

            if data.get('total') < self.opts['per_page']:
                break

# End of GO_dehashed class
