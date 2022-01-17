# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_pastebin
# Purpose:      Searches Google for PasteBin content related to the domain in
#               question.
#
# Author:      Steve Micallef <steve@binarypool.com> and ShellCodeNoobx
#
# Created:     20/03/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_pastebin(GhostOsintPlugin):

    meta = {
        'name': "PasteBin",
        'summary': "PasteBin (通过 Google 搜索 API) 搜索以识别相关内容.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://pastebin.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://pastebin.com/doc_api",
                "https://pastebin.com/faq"
            ],
            'apiKeyInstructions': [
                "访问 https://developers.google.com/custom-search/v1/introduction",
                "注册一个免费的 Google 账户",
                "点击 'Get A Key'",
                "连接项目",
                "API 密钥将在 'YOUR API KEY'"
            ],
            'favIcon': "https://pastebin.com/favicon.ico",
            'logo': "https://pastebin.com/favicon.ico",
            'description': "Pastebin 是一个可以在线存储任何文本以便于共享的网站. "
            "该网站主要由程序员用来存储源代码或配置信息，但欢迎任何人粘贴任何类型的文本. "
            "该网站背后的理念是让人们更方便地在线共享大量文本.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "cse_id": "013611106330597893267:tfgl3wxdtbp"
    }

    # Option descriptions
    optdescs = {
        "api_key": "Google API 密钥用于 PasteBin 搜索.",
        "cse_id": "Google 自定义搜索引擎 ID.",
    }

    domains = {
        'pastebin': "pastebin.com"
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
        return ["DOMAIN_NAME", "INTERNET_NAME", "EMAILADDR"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["LEAKSITE_CONTENT", "LEAKSITE_URL"]

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error(f"You enabled {self.__class__.__name__} but did not set a Google API key!")
            self.errorState = True
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        for dom in list(self.domains.keys()):
            target = self.domains[dom]
            res = self.GhostOsint.googleIterate(
                searchString=f'+site:{target} "{eventData}"',
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

            relevant_links = [
                link for link in new_links if self.GhostOsint.urlBaseUrl(link).endswith(target)
            ]

            for link in relevant_links:
                self.debug("Found a link: " + link)

                if self.checkForStop():
                    return

                res = self.GhostOsint.fetchUrl(link, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.debug(f"Ignoring {link} as no data returned")
                    continue

                if re.search(
                    r"[^a-zA-Z\-\_0-9]" + re.escape(eventData) + r"[^a-zA-Z\-\_0-9]",
                    res['content'],
                    re.IGNORECASE
                ) is None:
                    continue

                evt1 = GhostOsintEvent("LEAKSITE_URL", link, self.__name__, event)
                self.notifyListeners(evt1)

                evt2 = GhostOsintEvent("LEAKSITE_CONTENT", res['content'], self.__name__, evt1)
                self.notifyListeners(evt2)

# End of GO_pastebin class
