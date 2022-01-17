# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_ahmia
# Purpose:     Searches the Tor search engine 'Ahmia' for content related to the
#              target.
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     14/07/2019
# Copyright:   (c) Steve Micallef 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import urllib.error
import urllib.parse
import urllib.request

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_ahmia(GhostOsintPlugin):

    meta = {
        'name': "Ahmia Tor 搜索引擎",
        'flags': ["tor"],
        'summary': "在 Ahmia Tor 搜索引擎搜索目标信息.",
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://ahmia.fi/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://ahmia.fi/documentation/",
                "https://github.com/ahmia/",
                "http://msydqstlz2kzerdg.onion/",
                "https://ahmia.fi/stats"
            ],
            'favIcon': "https://ahmia.fi/static/images/favicon.ico",
            'logo': "https://ahmia.fi/static/images/ahmiafi_black.png",
            'description': "Ahmia 在 Tor 网络上搜索隐藏的服务. 要访问这些隐藏的服务,"
            "你需要安装 Tor 浏览器. 禁止滥用 Ahmia 提供的内容. "
            "如果您在索引中找到滥用材料，请查看我们的服务黑名单并报告. "
            "它将尽快被移除.\n"
            "Ahmia 贡献者认为 Tor是一个重要的 "
            "适用于全球匿名和隐私的弹性分布式平台. "
            "通过提供一个搜索引擎，许多人称之为 \"深网\" 或者 \"暗网\", "
            "Ahmia 让更多的人可以使用隐藏服务，而不仅仅是Tor网络的早期使用者."
        }
    }

    # Default options
    opts = {
        'fetchlinks': True,
        'fullnames': True
    }

    # Option descriptions
    optdescs = {
        'fetchlinks': "获取暗网页面 (如果启用则会通过 Tor ) 以验证你提交的目标是否在暗网中.",
        'fullnames': "搜索人名?"
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "HUMAN_NAME", "EMAILADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["DARKNET_MENTION_URL", "DARKNET_MENTION_CONTENT", "SEARCH_ENGINE_WEB_CONTENT"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if not self.opts['fullnames'] and eventName == 'HUMAN_NAME':
            self.debug(f"Skipping HUMAN_NAME: {eventData}")
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        params = urllib.parse.urlencode({
            'q': eventData
        })

        data = self.GhostOsint.fetchUrl(
            f"https://ahmia.fi/search/?{params}",
            useragent=self.opts['_useragent'],
            timeout=15
        )

        if not data:
            self.info(f"No results for {eventData} returned from Ahmia.fi.")
            return

        content = data.get('content')

        if not content:
            self.info(f"No results for {eventData} returned from Ahmia.fi.")
            return

        # We don't bother with pagination as Ahmia seems fairly limited in coverage
        # and displays hundreds of results per page
        links = re.findall("redirect_url=(.[^\"]+)\"", content, re.IGNORECASE | re.DOTALL)

        if not links:
            self.info(f"No results for {eventData} returned from Ahmia.fi.")
            return

        reported = False
        for link in links:
            if self.checkForStop():
                return

            if link in self.results:
                continue

            self.results[link] = True

            self.debug(f"Found a darknet mention: {link}")

            if not self.GhostOsint.urlFQDN(link).endswith(".onion"):
                continue

            if not self.opts['fetchlinks']:
                evt = GhostOsintEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                self.notifyListeners(evt)
                reported = True
                continue

            res = self.GhostOsint.fetchUrl(
                link,
                timeout=self.opts['_fetchtimeout'],
                useragent=self.opts['_useragent'],
                verify=False
            )

            if res['content'] is None:
                self.debug(f"Ignoring {link} as no data returned")
                continue

            if eventData not in res['content']:
                self.debug(f"Ignoring {link} as no mention of {eventData}")
                continue

            evt = GhostOsintEvent("DARKNET_MENTION_URL", link, self.__name__, event)
            self.notifyListeners(evt)
            reported = True

            try:
                startIndex = res['content'].index(eventData) - 120
                endIndex = startIndex + len(eventData) + 240
            except Exception:
                self.debug(f"String '{eventData}' not found in content.")
                continue

            wdata = res['content'][startIndex:endIndex]
            evt = GhostOsintEvent("DARKNET_MENTION_CONTENT", f"...{wdata}...", self.__name__, evt)
            self.notifyListeners(evt)

        if reported:
            # Submit the search results for analysis
            evt = GhostOsintEvent(
                "SEARCH_ENGINE_WEB_CONTENT",
                content,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

# End of GO_ahmia class
