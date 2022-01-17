# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_spyonweb
# Purpose:      GhostOSINT plug-in to search SpyOnWeb for hosts sharing the
#               same IP address, Google Analytics code, or Google Adsense code.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-25
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import datetime
import json
import time

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_spyonweb(GhostOsintPlugin):

    meta = {
        'name': "SpyOnWeb",
        'summary': "在 SpyOnWeb 中搜索共享IP地址的主机、Google Analytics代码或Google AdSense代码的主机.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "http://spyonweb.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://api.spyonweb.com/v1/docs",
                "https://api.spyonweb.com/"
            ],
            'apiKeyInstructions': [
                "访问 https://api.spyonweb.com",
                "登录或注册一个免费账户",
                "点击 'Dashboard'",
                "API 密钥将在 'Access Token'"
            ],
            'favIcon': "http://spyonweb.com/favicon.ico",
            'logo': "http://spyonweb.com/favicon.ico",
            'description': "我们从公共来源获取信息，然后构建它，以便你快速方便地搜索可能属于同一所有者的网站.",
        }
    }

    # Default options
    opts = {
        'api_key': '',
        'limit': 100,
        'timeout': 30,
        'maxage': 1095,   # 3 years
        'verify': True,
        'cohostsamedomain': False,
        'maxcohost': 100
    }

    # Option descriptions
    optdescs = {
        'api_key': "SpyOnWeb API 密钥.",
        'limit': "提取最大结果数.",
        'timeout': "查询超时（秒）.",
        'maxage': "返回的数据被视为有效的最长时间（天）.",
        'verify': "通过检查共享主机是否仍解析为共享IP地址来验证它们是否有效.",
        'cohostsamedomain': "将同一目标域上的托管站点视为共同托管?",
        'maxcohost': "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的.",
    }

    cohostcount = 0
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'INTERNET_NAME', 'DOMAIN_NAME', 'WEB_ANALYTICS_ID']

    # What events this module produces
    def producedEvents(self):
        return ['CO_HOSTED_SITE', 'INTERNET_NAME', 'AFFILIATE_INTERNET_NAME',
                'WEB_ANALYTICS_ID', 'DOMAIN_NAME', 'AFFILIATE_DOMAIN_NAME']

    # Query the REST API
    # https://api.spyonweb.com/v1/docs
    def query(self, endpoint, qry, limit=100):
        url = "https://api.spyonweb.com/v1/" + endpoint + "/" + qry
        url += "?limit=" + str(limit)
        url += "&access_token=" + self.opts['api_key']

        res = self.GhostOsint.fetchUrl(url, timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.debug("No results found for " + qry)
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        status = data.get('status')

        if status != 'found':
            self.debug("No results found for " + qry)
            return None

        api_result = data.get('result')

        if not api_result:
            self.debug("No results found for " + qry)
            return None

        endpoint_result = api_result.get(endpoint)

        if not endpoint_result:
            self.debug("No results found for " + qry)
            return None

        results = endpoint_result.get(qry)

        if not results:
            self.debug("No results found for " + qry)
            return None

        items = results.get('items')

        if not items:
            self.debug("No results found for " + qry)
            return None

        return items

    # Retrieve hosts with the specified Google Analytics ID
    def queryGoogleAnalytics(self, qry, limit=100):
        items = self.query('analytics', qry, limit)

        if not items:
            self.debug("No results found for " + qry)
            return None

        self.info("Retrieved " + str(len(items)) + " results")

        return items

    # Retrieve hosts with the specified Google AdSense ID
    def queryGoogleAdsense(self, qry, limit=100):
        items = self.query('adsense', qry, limit)

        if not items:
            self.debug("No results found for " + qry)
            return None

        self.info("Retrieved " + str(len(items)) + " results")

        return items

    # Retrieve hosts with the specified IP address
    def queryIP(self, qry, limit=100):
        items = self.query('ip', qry, limit)

        if not items:
            self.debug("No results found for " + qry)
            return None

        self.info("Retrieved " + str(len(items)) + " results")

        return items

    # Retrieve Google Analytics and Google AdSense IDs for the specified domain
    def querySummary(self, qry, limit=100):
        items = self.query('summary', qry, limit)

        if not items:
            self.debug("No results found for " + qry)
            return None

        self.info("Retrieved " + str(len(items)) + " results")

        return items

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled GO_spyonweb but did not set an API key!")
            self.errorState = True
            return

        agelimit = int(time.time() * 1000) - (86400000 * self.opts['maxage'])

        # Find Google AdSense IDs and Google Analytics IDs for the specified domain
        if eventName in ['INTERNET_NAME', 'DOMAIN_NAME']:
            data = self.querySummary(eventData, limit=self.opts['limit'])

            if data is None:
                self.info(f"No data found for {eventData}")
                return

            google_adsense = data.get('adsense')

            if google_adsense:
                for r in list(google_adsense.keys()):
                    evt = GhostOsintEvent("WEB_ANALYTICS_ID", f"Google AdSense: {r}", self.__name__, event)
                    self.notifyListeners(evt)

            google_analytics = data.get('analytics')

            if google_analytics:
                for r in list(google_analytics.keys()):
                    evt = GhostOsintEvent("WEB_ANALYTICS_ID", f"Google Analytics: {r}", self.__name__, event)
                    self.notifyListeners(evt)

        # Find affiliate domains for the specified Google AdSense ID or Google Analytics ID
        if eventName in ['WEB_ANALYTICS_ID']:
            try:
                network = eventData.split(": ")[0]
                analytics_id = eventData.split(": ")[1]
            except Exception as e:
                self.error(f"Unable to parse WEB_ANALYTICS_ID: {eventData} ({e})")
                return

            data = dict()
            if network == 'Google AdSense':
                data = self.queryGoogleAdsense(analytics_id, limit=self.opts['limit'])
            elif network == 'Google Analytics':
                data = self.queryGoogleAnalytics(analytics_id, limit=self.opts['limit'])
            else:
                return

            if data is None:
                self.info("No data found for " + eventData)
                return

            for r in list(data.keys()):
                last_seen = int(datetime.datetime.strptime(data[r], '%Y-%m-%d').strftime('%s')) * 1000

                if last_seen < agelimit:
                    self.debug("Record found too old, skipping.")
                    continue

                evt = GhostOsintEvent("AFFILIATE_INTERNET_NAME", r, self.__name__, event)
                self.notifyListeners(evt)

                if self.GhostOsint.isDomain(r, self.opts['_internettlds']):
                    evt = GhostOsintEvent("AFFILIATE_DOMAIN_NAME", r, self.__name__, event)
                    self.notifyListeners(evt)

        # Find co-hosts on the same IP address
        if eventName in ['IP_ADDRESS']:
            data = self.queryIP(eventData, limit=self.opts['limit'])

            if data is None:
                self.info("No data found for " + eventData)
                return

            self.cohostcount = 0

            for co in list(data.keys()):
                last_seen = int(datetime.datetime.strptime(data[co], '%Y-%m-%d').strftime('%s')) * 1000

                if last_seen < agelimit:
                    self.debug("Record found too old, skipping.")
                    continue

                if self.opts['verify'] and not self.GhostOsint.validateIP(co, eventData):
                    self.debug(f"Host {co} no longer resolves to {eventData}")
                    continue

                if not self.opts['cohostsamedomain']:
                    if self.getTarget().matches(co, includeParents=True):
                        evt = GhostOsintEvent("INTERNET_NAME", co, self.__name__, event)
                        self.notifyListeners(evt)
                        if self.GhostOsint.isDomain(co, self.opts['_internettlds']):
                            evt = GhostOsintEvent("DOMAIN_NAME", co, self.__name__, event)
                            self.notifyListeners(evt)
                        continue

                if self.cohostcount < self.opts['maxcohost']:
                    evt = GhostOsintEvent("CO_HOSTED_SITE", co, self.__name__, event)
                    self.notifyListeners(evt)
                    self.cohostcount += 1

# End of GO_spyonweb class
