# -------------------------------------------------------------------------------
# Name:        GO_grayhatwarfare
# Purpose:     Find bucket names matching the keyword extracted from a domain from Grayhat API.
#
# Author:      <krishnasis@hotmail.com>
#
# Created:     24-01-2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_grayhatwarfare(GhostOsintPlugin):

    meta = {
        'name': "Grayhat Warfare",
        'summary': "通过 Grayhat API 查找与从域名中提取的关键字所匹配的存储桶名称.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://buckets.grayhatwarfare.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://buckets.grayhatwarfare.com/docs/api/v1"
            ],
            'apiKeyInstructions': [
                "访问 https://grayhatwarfare.com/register",
                "注册一个账户",
                "访问 https://grayhatwarfare.com/account/settings",
                "API 密钥将在 'Api Key'",
            ],
            'favIcon': "https://buckets.grayhatwarfare.com/assets/template/images/favicon.png",
            'logo': "https://buckets.grayhatwarfare.com/assets/images/logo/logo-sm.png",
            'description': "它是一个开放存储桶的可搜索数据库."
            "每个桶有多达一百万个结果."
            "使用二进制逻辑进行全文搜索（可以搜索关键字，也可以搜索禁用词）",
        }
    }

    # Default options
    opts = {
        'api_key': '',
        'per_page': 1000,
        'max_pages': 2,
        'pause': 1
    }

    # Option descriptions
    optdescs = {
        'api_key': 'Grayhat Warfare API 密钥.',
        'per_page': '每页最大结果数 (Max: 1000).',
        'max_pages': '要提取的最大页数.',
        'pause': '每次API调用之间等待的秒数.'
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
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            'CLOUD_STORAGE_BUCKET',
            'CLOUD_STORAGE_BUCKET_OPEN',
            'RAW_RIR_DATA'
        ]

    # Query Grayhat Warfare
    def query(self, keyword, start):
        params = urllib.parse.urlencode({
            'keywords': keyword.encode('raw_unicode_escape'),
            'access_token': self.opts['api_key']
        })

        headers = {
            'Accept': 'application/json',
        }

        res = self.GhostOsint.fetchUrl(
            f"https://buckets.grayhatwarfare.com/api/v1/buckets/{start}/{self.opts['per_page']}?{params}",
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent'],
            verify=True
        )

        time.sleep(self.opts['pause'])

        if res['code'] != "200":
            self.error("Unable to fetch data from Grayhat Warfare API.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.debug('No response from Grayhat Warfare API.')
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

        if eventData in self.results:
            return

        if self.errorState:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled GO_grayhatwarfare but did not set an API key!")
            self.errorState = True
            return

        currentIndex = 0
        currentPage = 0
        maxPages = self.opts['max_pages']
        perPage = self.opts['per_page']

        keyword = self.GhostOsint.domainKeyword(eventData, self.opts['_internettlds'])

        while currentPage < maxPages:
            currentIndex = currentPage * perPage
            if self.checkForStop():
                return

            if self.errorState:
                break

            data = self.query(keyword=keyword, start=currentIndex)

            if not data:
                return

            for row in data.get('buckets'):
                bucketName = row.get('bucket')
                bucketKeyword = bucketName.split('.')[0]
                self.debug(bucketKeyword)
                if bucketKeyword.startswith(keyword) or bucketKeyword.endswith(keyword):
                    evt = GhostOsintEvent('CLOUD_STORAGE_BUCKET', bucketName, self.__name__, event)
                    self.notifyListeners(evt)

                    evt = GhostOsintEvent('CLOUD_STORAGE_BUCKET_OPEN', f"{bucketName}: {row.get('fileCount')} files found.", self.__name__, event)
                    self.notifyListeners(evt)

                    evt = GhostOsintEvent('RAW_RIR_DATA', str(row), self.__name__, event)
                    self.notifyListeners(evt)

            currentPage += 1
            if data.get('buckets_count') < perPage:
                break

# End of GO_grayhatwarfare class
