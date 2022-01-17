# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_whoisology
# Purpose:      Query whoisology.com using their API.
#
# Author:      Steve Micallef
#
# Created:     08/09/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_whoisology(GhostOsintPlugin):

    meta = {
        'name': "Whoisology",
        'summary': "使用 Whoisology.com 反向 Whois 查找.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://whoisology.com/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://whoisology.com/whois-database-download",
                "https://whoisology.com/tutorial"
            ],
            'apiKeyInstructions': [
                "访问 https://whoisology.com/",
                "注册一个免费账户",
                "导航到 https://whoisology.com/account",
                "点击 API Access",
                "付费访问后即可获得 API 密钥"
            ],
            'favIcon': "https://whoisology.com/img/w-logo.png",
            'logo': "https://whoisology.com/assets/images/il1.gif",
            'description': "Whoisology 是一个域名所有权档案，拥有数十亿可搜索和交叉引用的域名 whois 记录. "
            "我们的主要关注点是反向 whois ，用于网络犯罪调查/信息安全、企业情报、法律研究、业务发展和良好的侦查. ",
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "api_key": "Whoisology.com API 密钥.",
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

    # Search Whoisology
    def query(self, qry, querytype):
        url = "https://whoisology.com/api?auth=" + self.opts['api_key'] + "&request=flat"
        url += "&field=" + querytype + "&value=" + qry + "&level=Registrant|Admin|Tec|Billing|Other"

        res = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent="GhostOSINT")

        if res['code'] in ["400", "429", "500", "403"]:
            self.error("Whoisology API key seems to have been rejected or you have exceeded usage limits.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info(f"No Whoisology info found for {qry}")
            return None

        try:
            info = json.loads(res['content'])
            if info.get("domains") is None:
                self.error("Error querying Whoisology: " + info.get("status_reason", "Unknown"))
                return None

            if len(info.get("domains", [])) == 0:
                self.debug(f"No data found in Whoisology for {qry}")
                return None

            return info.get('domains')
        except Exception as e:
            self.error(f"Error processing JSON response from Whoisology: {e}")
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
            self.error("You enabled GO_whoisology but did not set an API key!")
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

# End of GO_whoisology class
