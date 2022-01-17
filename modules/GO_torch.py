# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_torch
# Purpose:      Searches the Tor search engine 'TORCH' for content related
#               to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/06/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from urllib.parse import urlencode

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_torch(GhostOsintPlugin):

    meta = {
        'name': "TORCH",
        'summary': "在 Tor 'TORCH' 搜索引擎中搜索目标域名的相关信息.",
        'flags': ["errorprone", "tor"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://torchsearch.wordpress.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Torch 或 TorSearch 是互联网隐藏部分的最佳搜索引擎. "
                "他们也是Tor上最古老、运行时间最长的搜索引擎.\n"
                "Torch 声称有超过10亿个暗网页面被索引. "
                "他们也不会审查搜索结果或跟踪你搜索的内容.",
        }
    }

    opts = {
        'fetchlinks': True,
        'pages': 20,
        'fullnames': True
    }

    optdescs = {
        'fetchlinks': "获取暗网页面（如果启用则通过 Tor ）以验证它们是否与目标相关.",
        'pages': "访问结果页数.",
        'fullnames': "搜索人名?"
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "HUMAN_NAME",
            "EMAILADDR"
        ]

    def producedEvents(self):
        return [
            "DARKNET_MENTION_URL",
            "DARKNET_MENTION_CONTENT",
            "SEARCH_ENGINE_WEB_CONTENT"
        ]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if not self.opts['fullnames'] and eventName == 'HUMAN_NAME':
            return

        if eventData in self.results:
            self.debug(f"Already did a search for {eventData}, skipping.")
            return

        self.results[eventData] = True

        formpage = self.GhostOsint.fetchUrl(
            "http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/",
            useragent=self.opts['_useragent'],
            timeout=60)

        if not formpage['content']:
            self.info("Couldn't connect to TORCH, it might be down.")
            return

        if "<b>0</b> results" in formpage['content']:
            self.info(f"No results found on TORCH for {eventData}")
            return

        pagecount = 0
        while pagecount < self.opts['pages']:
            # Check if we've been asked to stop
            if self.checkForStop():
                return

            # Sites hosted on the domain
            params = {"action": "search", "query": eventData}
            if pagecount > 0:
                params['page'] = pagecount
            pagecount += 1

            qry = urlencode(params)
            data = self.GhostOsint.fetchUrl(
                f"http://torchdeedp3i2jigzjdmfpn5ttjhthh5wbmda2rr3jvqjg5p77c54dqd.onion/search?{qry}",
                useragent=self.opts['_useragent'],
                timeout=60)

            if data is None or not data.get('content'):
                self.info("No results returned from TORCH.")
                return

            links = re.findall(r'<h5><a href="(.*?)"\s+target="_blank">',
                               data['content'], re.IGNORECASE)

            linkcount = 0
            for link in links:
                if link in self.results:
                    continue

                linkcount += 1
                self.results[link] = True
                self.debug(f"Found a darknet mention: {link}")
                if self.GhostOsint.urlFQDN(link).endswith(".onion"):
                    if self.checkForStop():
                        return
                    if self.opts['fetchlinks']:
                        res = self.GhostOsint.fetchUrl(link, timeout=self.opts['_fetchtimeout'],
                                               useragent=self.opts['_useragent'])

                        if res['content'] is None:
                            self.debug(f"Ignoring {link} as no data returned")
                            continue

                        if eventData not in res['content']:
                            self.debug(f"Ignoring {link} as no mention of {eventData}")
                            continue
                        evt = GhostOsintEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                        self.notifyListeners(evt)

                        try:
                            startIndex = res['content'].index(eventData) - 120
                            endIndex = startIndex + len(eventData) + 240
                        except Exception:
                            self.debug("String not found in content.")
                            continue

                        darkcontent = res['content'][startIndex:endIndex]
                        evt = GhostOsintEvent("DARKNET_MENTION_CONTENT", f"...{darkcontent}...",
                                              self.__name__, evt)
                        self.notifyListeners(evt)

                    else:
                        evt = GhostOsintEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                        self.notifyListeners(evt)

            if linkcount > 0:
                # Submit the search results for analysis elsewhere
                evt = GhostOsintEvent("SEARCH_ENGINE_WEB_CONTENT", data['content'],
                                      self.__name__, event)
                self.notifyListeners(evt)
            else:
                # No more pages
                return


# End of GO_torch class
