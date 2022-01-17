# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_onionsearchengine
# Purpose:      Searches the Tor search engine onionsearchengine.com for content
#               related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     27/10/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import urllib.error
import urllib.parse
import urllib.request

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_onionsearchengine(GhostOsintPlugin):

    meta = {
        'name': "Onionsearchengine.com",
        'summary': "搜索 Tor onionsearchengine.com 中搜索目标域名的相关信息.",
        'flags': ["tor"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://as.onionsearchengine.com",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://helpdesk.onionsearchengine.com/?v=knowledgebase",
                "https://onionsearchengine.com/add_url.php"
            ],
            'favIcon': "https://as.onionsearchengine.com/images/onionsearchengine.jpg",
            'logo': "https://as.onionsearchengine.com/images/onionsearchengine.jpg",
            'description': "没有 cookie，没有 javascript，没有跟踪。我们保护你的隐私.\n"
            "洋葱搜索引擎是一种能够在tor 网络/深网/暗网上查找内容的搜索引擎.",
        }
    }

    # Default options
    opts = {
        'timeout': 10,
        'max_pages': 20,
        'fetchlinks': True,
        'blacklist': ['.*://relate.*'],
        'fullnames': True
    }

    # Option descriptions
    optdescs = {
        'timeout': "查询超时（秒）.",
        'max_pages': "提取结果最大页数.",
        'fetchlinks': "获取暗网页面（如果启用则通过 Tor ）以验证它们是否与目标相关.",
        'blacklist': "从与这些模式匹配的网站中排除结果.",
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
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DARKNET_MENTION_URL", "DARKNET_MENTION_CONTENT", "SEARCH_ENGINE_WEB_CONTENT"]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if not self.opts['fullnames'] and eventName == 'HUMAN_NAME':
            return

        if eventData in self.results:
            self.debug("Already did a search for " + eventData + ", skipping.")
            return

        self.results[eventData] = True

        keepGoing = True
        page = 1
        while keepGoing and page <= int(self.opts['max_pages']):
            # Check if we've been asked to stop
            if self.checkForStop():
                return

            params = {
                'search': '"' + eventData.encode('raw_unicode_escape').decode("ascii", errors='replace') + '"',
                'submit': 'Search',
                'page': str(page)
            }

            # Sites hosted on the domain
            data = self.GhostOsint.fetchUrl('https://onionsearchengine.com/search.php?' + urllib.parse.urlencode(params),
                                    useragent=self.opts['_useragent'],
                                    timeout=self.opts['timeout'])

            if data is None or not data.get('content'):
                self.info("No results returned from onionsearchengine.com.")
                return

            page += 1

            if "url.php?u=" not in data['content']:
                # Work around some kind of bug in the site
                if "you didn't submit a keyword" in data['content']:
                    continue
                return

            if "forward >" not in data['content']:
                keepGoing = False

            # Submit the google results for analysis
            evt = GhostOsintEvent("SEARCH_ENGINE_WEB_CONTENT", data['content'],
                                  self.__name__, event)
            self.notifyListeners(evt)

            links = re.findall(r"url\.php\?u=(.[^\"\']+)[\"\']",
                               data['content'], re.IGNORECASE | re.DOTALL)

            for link in links:
                if self.checkForStop():
                    return

                if link in self.results:
                    continue

                self.results[link] = True

                blacklist = False
                for r in self.opts['blacklist']:
                    if re.match(r, link, re.IGNORECASE):
                        self.debug("Skipping " + link + " as it matches blacklist " + r)
                        blacklist = True
                if blacklist:
                    continue

                self.debug("Found a darknet mention: " + link)

                if not self.GhostOsint.urlFQDN(link).endswith(".onion"):
                    continue

                if not self.opts['fetchlinks']:
                    evt = GhostOsintEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                    self.notifyListeners(evt)
                    continue

                res = self.GhostOsint.fetchUrl(link,
                                       timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'],
                                       verify=False)

                if res['content'] is None:
                    self.debug("Ignoring " + link + " as no data returned")
                    continue

                if eventData not in res['content']:
                    self.debug("Ignoring " + link + " as no mention of " + eventData)
                    continue

                evt = GhostOsintEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                self.notifyListeners(evt)

                try:
                    startIndex = res['content'].index(eventData) - 120
                    endIndex = startIndex + len(eventData) + 240
                except Exception:
                    self.debug('String "' + eventData + '" not found in content.')
                    continue

                data = res['content'][startIndex:endIndex]
                evt = GhostOsintEvent("DARKNET_MENTION_CONTENT", "..." + data + "...",
                                      self.__name__, evt)
                self.notifyListeners(evt)

# End of GO_onionsearchengine class
