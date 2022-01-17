# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_whoxy
# Purpose:      Query whoxy.com using their API.
#
# Author:      Steve Micallef
#
# Created:     03/09/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_whoxy(GhostOsintPlugin):

    meta = {
        'name': "Whoxy",
        'summary': "使用 Whoxy.com 反向 Whois 查找.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.whoxy.com/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://www.whoxy.com/#api",
                "https://www.whoxy.com/whois-history/",
                "https://www.whoxy.com/free-whois-api/"
            ],
            'apiKeyInstructions': [
                "访问 https://www.whoxy.com/pricing.php",
                "选择计划并注册帐户",
                "支付计划费用",
                "API 密钥将在付款时提供"
            ],
            'favIcon': "https://www.whoxy.com/favicon.ico",
            'logo': "https://www.whoxy.com/images/logo.png",
            'description': "Whois API 是一个托管的 WEB 服务，它以流行的 XM L和 JSON 格式为每个 HTTP 请求向应用程序返回解析良好的 WHOIS 字段. "
            "把所有的辛苦工作留给我们吧，因为你不必担心各种域名注册商强加的查询限制和限制.",
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "api_key": "Whoxy.com API 密钥.",
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["EMAILADDR"]

    # What events this module produces
    def producedEvents(self):
        return ['AFFILIATE_INTERNET_NAME', 'AFFILIATE_DOMAIN_NAME']

    # Search Whoxy
    def query(self, qry, querytype, page=1, accum=None):
        info = None

        url = "https://api.whoxy.com/?key=" + self.opts['api_key'] + "&reverse=whois"
        url += "&" + querytype + "=" + qry + "&page=" + str(page)

        res = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent="GhostOSINT")

        if res['code'] in ["400", "429", "500", "403"]:
            self.error("Whoxy API key seems to have been rejected or you have exceeded usage limits.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info("No Whoxy info found for " + qry)
            return None

        try:
            info = json.loads(res['content'])
            if info.get("status", 0) == 0:
                self.error("Error querying Whoxy: " + info.get("status_reason", "Unknown"))
                self.errorState = True
                return None
            if info.get("total_pages", 1) > 1:
                if info.get("current_page") < info.get("total_pages"):
                    if accum:
                        accum.extend(info.get('search_result'))
                    else:
                        accum = info.get('search_result')
                    return self.query(qry, querytype, page + 1, accum)
                else:
                    # We are at the last page
                    accum.extend(info.get('search_result', []))
                    return accum
            else:
                return info.get('search_result', [])
        except Exception as e:
            self.error("Error processing JSON response from Whoxy: " + str(e))
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled GO_whoxy but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        rec = self.query(eventData, "email")
        myres = list()
        if rec is not None:
            for r in rec:
                h = r.get('domain_name')
                if h:
                    if h.lower() not in myres:
                        myres.append(h.lower())
                    else:
                        continue

                    e = GhostOsintEvent("AFFILIATE_INTERNET_NAME", h, self.__name__, event)
                    self.notifyListeners(e)

                    if self.GhostOsint.isDomain(h, self.opts['_internettlds']):
                        evt = GhostOsintEvent('AFFILIATE_DOMAIN_NAME', h, self.__name__, event)
                        self.notifyListeners(evt)

# End of GO_whoxy class
