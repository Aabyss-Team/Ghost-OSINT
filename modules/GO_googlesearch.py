# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_googlesearch
# Purpose:      Searches Google for content related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/05/2012
# Copyright:   (c) Snow Wolf 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_googlesearch(GhostOsintPlugin):

    meta = {
        'name': "Google",
        'summary': "从 Google 自定义搜索 API 中获取信息以识别子域名和链接.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://developers.google.com/custom-search",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://developers.google.com/custom-search/v1",
                "https://developers.google.com/custom-search/docs/overview",
                "https://cse.google.com/cse"
            ],
            'apiKeyInstructions': [
                "访问 https://developers.google.com/custom-search/v1/introduction",
                "注册一个免费的 Google 账户",
                "点击 'Get A Key'",
                "连接项目",
                "API 密钥将在 'YOUR API KEY'"
            ],
            'favIcon': "https://www.gstatic.com/devrel-devsite/prod/v2210deb8920cd4a55bd580441aa58e7853afc04b39a9d9ac4198e1cd7fbe04ef/developers/images/favicon.png",
            'logo': "https://www.gstatic.com/devrel-devsite/prod/v2210deb8920cd4a55bd580441aa58e7853afc04b39a9d9ac4198e1cd7fbe04ef/developers/images/favicon.png",
            'description': "Google 自定义搜索使你能够为你的网站、博客或网站集合创建搜索引擎. "
            "你可以将引擎配置为同时搜索网页和图像. "
            "你可以微调排名，添加自己的促销活动，自定义搜索结果的外观和感觉. "
            "你可以通过将你的搜索引擎连接到你的 Google AdSense 帐户来赚钱.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "cse_id": "013611106330597893267:tfgl3wxdtbp"
    }

    # Option descriptions
    optdescs = {
        "api_key": "Google API 密钥用来 Google 查询.",
        "cse_id": "Google 自定义搜索引擎 ID."
    }

    # Target
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
            self.error("You enabled GO_googlesearch but did not set a Google API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug("Already did a search for " + eventData + ", skipping.")
            return

        self.results[eventData] = True

        # Sites hosted on the domain
        res = self.GhostOsint.googleIterate(
            searchString="site:" + eventData,
            opts={
                "timeout": self.opts["_fetchtimeout"],
                "useragent": self.opts["_useragent"],
                "api_key": self.opts["api_key"],
                "cse_id": self.opts["cse_id"],
            },
        )
        if res is None:
            # Failed to talk to the Google API or no results returned
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

# End of GO_googlesearch class
