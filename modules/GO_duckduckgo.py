# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_duckduckgo
# Purpose:      Queries DuckDuckGo's API for information abotut the target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     21/07/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_duckduckgo(GhostOsintPlugin):

    meta = {
        'name': "DuckDuckGo",
        'summary': "查询 DuckDuckGo 的 API 以获取有关目标的详细信息.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://duckduckgo.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://api.duckduckgo.com/api",
                "https://help.duckduckgo.com/company/partnerships/",
                "https://help.duckduckgo.com/duckduckgo-help-pages/"
            ],
            'favIcon': "https://duckduckgo.com/favicon.ico",
            'logo': "https://duckduckgo.com/assets/icons/meta/DDG-icon_256x256.png",
            'description': "我们的即时显示 API 允许您免费访问我们的许多即时内容，如: "
            "主题摘要 , 类别, 解疑, and 芜湖! 重定向.",
        }
    }

    # Default options
    opts = {
        "affiliatedomains": True
    }

    # Option descriptions
    optdescs = {
        "affiliatedomains": "对于分支机构会查找域名，而不是主机名。这通常会返回有关企业的信息."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "DOMAIN_NAME_PARENT",
                "INTERNET_NAME", "AFFILIATE_INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DESCRIPTION_CATEGORY", "DESCRIPTION_ABSTRACT",
                "AFFILIATE_DESCRIPTION_CATEGORY",
                "AFFILIATE_DESCRIPTION_ABSTRACT"]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.opts['affiliatedomains'] and "AFFILIATE_" in eventName:
            eventData = self.GhostOsint.hostDomain(eventData, self.opts['_internettlds'])
            if not eventData:
                return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        url = "https://api.duckduckgo.com/?q=" + eventData + "&format=json&pretty=1"
        res = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent="GhostOSINT")

        if res['content'] is None:
            self.error(f"Unable to fetch {url}")
            return

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from DuckDuckGo: {e}")
            return

        if not ret['Heading']:
            self.debug(f"No DuckDuckGo information for {eventData}")
            return

        # Submit the DuckDuckGo results for analysis
        evt = GhostOsintEvent("SEARCH_ENGINE_WEB_CONTENT", res['content'],
                              self.__name__, event)
        self.notifyListeners(evt)

        abstract_text = ret.get('AbstractText')
        if abstract_text:
            event_type = "DESCRIPTION_ABSTRACT"

            if "AFFILIATE" in eventName:
                event_type = "AFFILIATE_" + event_type

            evt = GhostOsintEvent(event_type, str(abstract_text), self.__name__, event)
            self.notifyListeners(evt)

        related_topics = ret.get('RelatedTopics')
        if related_topics:
            event_type = "DESCRIPTION_CATEGORY"

            if "AFFILIATE" in eventName:
                event_type = "AFFILIATE_" + event_type

            for topic in related_topics:
                if not isinstance(topic, dict):
                    self.debug("No category text found from DuckDuckGo.")
                    continue

                category = topic.get('Text')

                if not category:
                    self.debug("No category text found from DuckDuckGo.")
                    continue

                evt = GhostOsintEvent(event_type, category, self.__name__, event)
                self.notifyListeners(evt)

# End of GO_duckduckgo class
