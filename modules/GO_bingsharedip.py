# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_bingsharedip
# Purpose:      Searches Bing for hosts sharing the same IP.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_bingsharedip(GhostOsintPlugin):

    meta = {
        'name': "Bing (共享主机IP搜索)",
        'summary': "在 Bing 中搜索共享IP地址的主机.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.bing.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.microsoft.com/en-us/azure/cognitive-services/bing-web-search/"
            ],
            'apiKeyInstructions': [
                "访问 https://azure.microsoft.com/en-in/services/cognitive-services/bing-web-search-api/",
                "注册一个免费账户",
                "在 Bing 上自定义搜索",
                "API 密钥将在 'Key1' 和 'Key2' (两个都能用)"
            ],
            'favIcon': "https://www.bing.com/sa/simg/bing_p_rr_teal_min.ico",
            'logo': "https://www.bing.com/sa/simg/bing_p_rr_teal_min.ico",
            'description': "Bing 搜索 API 允许你构建网络连接的应用程序和服务 "
            ", 在没有广告的情况下查找网页、图片、新闻、位置等.",
        }
    }

    # Default options
    opts = {
        "cohostsamedomain": False,
        "pages": 20,
        "verify": True,
        "maxcohost": 100,
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "cohostsamedomain": "将同一目标域上的共同托管站点视为共同托管?",
        "pages": "从 API 请求的 bing 最大结果数.",
        "verify": "通过检查协作主机是否仍解析为共享IP地址来验证它们是否有效.",
        "maxcohost": "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的.",
        "api_key": "Bing API 密钥."
    }

    results = None
    cohostcount = 0
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0
        self.__dataSource__ = "Bing"
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["CO_HOSTED_SITE", "IP_ADDRESS", "RAW_RIR_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "" and self.opts['api_key'] == "":
            self.error("You enabled GO_bingsharedip but did not set a Bing API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        # Ignore IP addresses from myself as they are just for creating
        # a link from the netblock to the co-host.
        if eventName == "IP_ADDRESS" and srcModuleName == "GO_bingsharedip":
            self.debug("Ignoring " + eventName + ", from self.")
            return

        if self.cohostcount > self.opts["maxcohost"]:
            return

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                if str(ipaddr) not in self.results:
                    qrylist.append(str(ipaddr))
                    self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)
            self.results[eventData] = True

        myres = list()

        for ip in qrylist:
            if self.checkForStop():
                return

            res = self.GhostOsint.bingIterate(
                searchString="ip:" + ip,
                opts={
                    "timeout": self.opts["_fetchtimeout"],
                    "useragent": self.opts["_useragent"],
                    "count": self.opts["pages"],
                    "api_key": self.opts["api_key"],
                },
            )
            if res is None:
                # Failed to talk to bing api or no results returned
                return

            urls = res["urls"]

            for url in urls:
                self.info("Found something on same IP: " + url)
                site = self.GhostOsint.urlFQDN(url.lower())
                if site not in myres and site != ip:
                    if not self.opts["cohostsamedomain"]:
                        if self.getTarget().matches(site, includeParents=True):
                            self.debug(
                                f"Skipping {site} because it is on the same domain."
                            )
                            continue
                    if self.opts["verify"] and not self.GhostOsint.validateIP(site, ip):
                        self.debug(f"Host {site} no longer resolves to {ip}")
                        continue
                    # Create an IP Address event stemming from the netblock as the
                    # link to the co-host.
                    if eventName == "NETBLOCK_OWNER":
                        ipe = GhostOsintEvent("IP_ADDRESS", ip, self.__name__, event)
                        self.notifyListeners(ipe)
                        evt = GhostOsintEvent(
                            "CO_HOSTED_SITE", site, self.__name__, ipe
                        )
                        self.notifyListeners(evt)
                    else:
                        evt = GhostOsintEvent(
                            "CO_HOSTED_SITE", site, self.__name__, event
                        )
                        self.notifyListeners(evt)
                    self.cohostcount += 1
                    myres.append(site)

            if urls:
                evt = GhostOsintEvent(
                    "RAW_RIR_DATA", str(res), self.__name__, event
                )
                self.notifyListeners(evt)

# End of GO_bingsharedip class
