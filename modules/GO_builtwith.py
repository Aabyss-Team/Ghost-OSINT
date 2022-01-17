# -------------------------------------------------------------------------------
# Name:         GO_builtwith
# Purpose:      Query builtwith.com using their API.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     10/08/2017
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_builtwith(GhostOsintPlugin):

    meta = {
        'name': "BuiltWith",
        'summary': "查询 BuiltWith.com's 域名 API 来获取目标的WEB技术堆栈、电子邮件地址等信息.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://builtwith.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://api.builtwith.com/",
                "https://kb.builtwith.com/",
                "https://builtwith.com/screencast",
                "https://builtwith.com/faq"
            ],
            'apiKeyInstructions': [
                "访问 https://api.builtwith.com/free-api",
                "注册一个免费账户",
                "导航到 https://api.builtwith.com/free-api",
                "API 密钥将在 'Your API Key'"
            ],
            'favIcon': "https://d28rh9vvmrd65v.cloudfront.net/favicon.ico",
            'logo': "https://d28rh9vvmrd65v.cloudfront.net/favicon.ico",
            'description': "从我们 38701+ 的网络技术数据库和超过25亿个网站的网站列表，显示哪些网站使用购物车、分析、托管等. "
            "按位置、交通、垂直等进行过滤。在与潜在客户交谈之前，了解他们的平台.\n"
            "通过验证市场采用率提高转化率. \n"
            "获取所有网络技术的先进技术市场份额信息和基于国家或地区的分析.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "maxage": 30
    }

    # Option descriptions
    optdescs = {
        "api_key": "Builtwith.com 域名 API 密钥.",
        "maxage": "返回的数据被视为有效的最长时间（天）."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "EMAILADDR", "EMAILADDR_GENERIC", "RAW_RIR_DATA",
                "WEBSERVER_TECHNOLOGY", "PHONE_NUMBER", "DOMAIN_NAME",
                "CO_HOSTED_SITE", "IP_ADDRESS", "WEB_ANALYTICS_ID"]

    def queryRelationships(self, t):
        url = f"https://api.builtwith.com/rv1/api.json?LOOKUP={t}&KEY={self.opts['api_key']}"

        res = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent="GhostOSINT")

        if res['code'] == "404":
            return None

        if not res['content']:
            return None

        try:
            return json.loads(res['content'])['Relationships']
        except Exception as e:
            self.error(f"Error processing JSON response from builtwith.com: {e}")

        return None

    def queryDomainInfo(self, t):
        url = f"https://api.builtwith.com/rv1/api.json?LOOKUP={t}&KEY={self.opts['api_key']}"

        res = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent="GhostOSINT")

        if res['code'] == "404":
            return None

        if not res['content']:
            return None

        try:
            return json.loads(res['content'])['Results'][0]
        except Exception as e:
            self.error(f"Error processing JSON response from builtwith.com: {e}")

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
            self.error("You enabled GO_builtwith but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.queryDomainInfo(eventData)
        if data is not None:
            if "Meta" in data:
                if data['Meta'].get("Names", []):
                    for nb in data['Meta']['Names']:
                        e = GhostOsintEvent("RAW_RIR_DATA", "Possible full name: " + nb['Name'],
                                            self.__name__, event)
                        self.notifyListeners(e)
                        if nb.get('Email', None):
                            if self.GhostOsint.validEmail(nb['Email']):
                                if nb['Email'].split("@")[0] in self.opts['_genericusers'].split(","):
                                    evttype = "EMAILADDR_GENERIC"
                                else:
                                    evttype = "EMAILADDR"
                                e = GhostOsintEvent(evttype, nb['Email'],
                                                    self.__name__, event)
                                self.notifyListeners(e)

                if data['Meta'].get("Emails", []):
                    for email in data['Meta']['Emails']:
                        if self.GhostOsint.validEmail(email):
                            if email.split("@")[0] in self.opts['_genericusers'].split(","):
                                evttype = "EMAILADDR_GENERIC"
                            else:
                                evttype = "EMAILADDR"

                            e = GhostOsintEvent(evttype, email,
                                                self.__name__, event)
                            self.notifyListeners(e)

                if data['Meta'].get("Telephones", []):
                    for phone in data['Meta']['Telephones']:
                        phone = phone.replace("-", "").replace("(", "").replace(")", "").replace(" ", "")
                        e = GhostOsintEvent("PHONE_NUMBER", phone, self.__name__, event)
                        self.notifyListeners(e)

            if "Paths" in data.get("Result", []):
                for p in data["Result"]['Paths']:
                    if p.get("SubDomain", ""):
                        h = p["SubDomain"] + "." + eventData
                        ev = GhostOsintEvent("INTERNET_NAME", h, self.__name__, event)
                        self.notifyListeners(ev)
                        if self.GhostOsint.isDomain(h, self.opts['_internettlds']):
                            ev = GhostOsintEvent("DOMAIN_NAME", h, self.__name__, event)
                            self.notifyListeners(ev)
                    else:
                        ev = None

                    # If we have a subdomain, let's get its tech info
                    # and associate it with the subdomain event.
                    for t in p.get("Technologies", []):
                        if ev:
                            src = ev
                        else:
                            src = event
                        agelimit = int(time.time() * 1000) - (86400000 * self.opts['maxage'])
                        if t.get("LastDetected", 0) < agelimit:
                            self.debug("Data found too old, skipping.")
                            continue
                        e = GhostOsintEvent("WEBSERVER_TECHNOLOGY", t["Name"],
                                            self.__name__, src)
                        self.notifyListeners(e)

        data = self.queryRelationships(eventData)
        if data is None:
            return

        agelimit = int(time.time() * 1000) - (86400000 * self.opts['maxage'])

        for r in data:
            if "Domain" not in r or "Identifiers" not in r:
                self.debug("Data returned not in the format requested.")
                continue

            if r['Domain'] != eventData:
                self.debug("Data returned doesn't match data requested, skipping.")
                continue

            for i in r['Identifiers']:
                if "Last" not in i or "Type" not in i or "Value" not in i:
                    self.debug("Data returned not in the format requested.")
                    continue

                if i['Last'] < agelimit:
                    self.debug("Data found too old, skipping.")
                    continue

                evttype = None
                # Related through shared IP
                if i['Type'] == "ip":
                    if self.GhostOsint.validIP(i['Value']):
                        val = i['Value']
                        evttype = "IP_ADDRESS"
                    else:
                        val = i['Value'].strip(".")
                        if self.getTarget.matches(val):
                            evttype = "INTERNET_NAME"
                        else:
                            evttype = "CO_HOSTED_SITE"

                    # Create the name/co-host
                    e = GhostOsintEvent(evttype, val, self.__name__, event)
                    self.notifyListeners(e)
                    continue

                # Related through shared analytics ID
                txt = i['Type'] + ": " + str(i['Value'])
                e = GhostOsintEvent("WEB_ANALYTICS_ID", txt, self.__name__, event)
                self.notifyListeners(e)

                if i['Matches']:
                    for m in i['Matches']:
                        if "Domain" not in m:
                            continue
                        evt = GhostOsintEvent("AFFILIATE_INTERNET_NAME", m['Domain'], self.__name__, e)
                        self.notifyListeners(evt)

                        if self.GhostOsint.isDomain(m['Domain'], self.opts['_internettlds']):
                            evt = GhostOsintEvent("AFFILIATE_DOMAIN_NAME", m['Domain'], self.__name__, e)
                            self.notifyListeners(evt)

# End of GO_builtwith class
