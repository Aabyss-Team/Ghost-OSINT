# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_bingsearch
# Purpose:      Searches Bing for content related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/10/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
# -------------------------------------------------------------------------------
from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_bingsearch(GhostOsintPlugin):

    meta = {
        'name': "Bing搜索",
        'summary': "通过 Bing 获取信息以识别子域和链接.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.bing.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.microsoft.com/en-us/azure/cognitive-services/bing-web-search/"
            ],
            'apiKeyInstructions': [
                "访问 https://azure.microsoft.com/en-in/services/cognitive-services/bing-web-search-api/",
                "注册一个免费用户",
                "在 Bing 自定义搜索选择",
                "API 密钥将在 'Key1' 和 'Key2' (两个都可以)"
            ],
            'favIcon': "https://www.bing.com/sa/simg/bing_p_rr_teal_min.ico",
            'logo': "https://www.bing.com/sa/simg/bing_p_rr_teal_min.ico",
            'description': "Bing 搜索 API 允许你构建网络连接的应用程序和服务 "
            ", 在没有广告的情况下查找网页、图片、新闻、位置等.",
        }
    }

    # Default options
    opts = {
        "pages": 20,
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "pages": "从 API 请求的 bing 最大结果数.",
        "api_key": "Bing API 密钥 ."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["LINKED_URL_INTERNAL", "RAW_RIR_DATA"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled GO_bingsearch but did not set a Bing API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug("Already did a search for " + eventData + ", skipping.")
            return

        self.results[eventData] = True

        # Sites hosted on the domain

        res = self.GhostOsint.bingIterate(
            searchString="site:" + eventData,
            opts={
                "timeout": self.opts["_fetchtimeout"],
                "useragent": self.opts["_useragent"],
                "count": self.opts["pages"],
                "api_key": self.opts["api_key"],
            },
        )
        if res is None:
            # Failed to talk to the bing API or no results returned
            return

        urls = res["urls"]
        new_links = list(set(urls) - set(self.results.keys()))

        # Add new links to results
        for link in new_links:
            self.results[link] = True

        internal_links = [
            link for link in new_links if self.GhostOsint.urlFQDN(link).endswith(eventData)
        ]
        for link in internal_links:
            self.debug("Found a link: " + link)

            evt = GhostOsintEvent("LINKED_URL_INTERNAL", link, self.__name__, event)
            self.notifyListeners(evt)

        if internal_links:
            evt = GhostOsintEvent(
                "RAW_RIR_DATA", str(res), self.__name__, event
            )
            self.notifyListeners(evt)

# End of GO_bingsearch class
