# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_projectdiscovery
# Purpose:      Search for hosts/subdomains using chaos.projectdiscovery.io
#
# Author:      Filip Aleksić <faleksicdev@gmail.com>
#
# Created:     2020-09-04
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_projectdiscovery(GhostOsintPlugin):
    meta = {
        "name": "ProjectDiscovery Chaos",
        "summary": "通过 chaos.projectdiscovery.io 搜索主机或子域名",
        'flags': ["apikey"],
        "useCases": ["Passive", "Footprint", "Investigate"],
        "categories": ["Passive DNS"],
        "dataSource": {
            "website": "https://chaos.projectdiscovery.io",
            "model": "PRIVATE_ONLY",
            "references": [
                "https://chaos.projectdiscovery.io/#/docs",
                "https://projectdiscovery.io/privacy",
                "https://projectdiscovery.io/about",
            ],
            "apiKeyInstructions": [
                "访问 https://chaos.projectdiscovery.io/#/",
                "单击'请求访问'按钮",
                "点击 'Early signup form' 连接跳转到 https://forms.gle/GP5nTamxJPfiMaBn9",
                "点击 'Developer'",
                "API 密钥将在 'Your API Key'",
                "你将通过电子邮件收到你的API密钥.",
            ],
            "logo": "https://projectdiscovery.io/assets/img/logo.png",
            "description": "Projectdiscovery Chaos 积极收集和维护互联网范围内资产的数据，该项目旨在加强对DNS变化的研究和分析，以获得更好的见解. ",
        },
    }

    opts = {
        "api_key": "",
        "verify": True,
    }
    optdescs = {
        "api_key": "chaos.projectdiscovery.io API 密钥.",
        "verify": "验证在目标域上找到的任何主机名是否仍可解析?",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    def producedEvents(self):
        return ["RAW_RIR_DATA", "INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]

    def query(self, qry):
        headers = {"Accept": "application/json", "Authorization": self.opts["api_key"]}
        res = self.GhostOsint.fetchUrl(
            f"https://dns.projectdiscovery.io/dns/{qry}/subdomains",
            timeout=self.opts["_fetchtimeout"],
            useragent="GhostOSINT",
            headers=headers,
        )

        if res["content"] is None:
            self.info("No DNS info found in chaos projectdiscovery API for " + qry)
            return None

        try:
            return json.loads(res["content"])
        except json.JSONDecodeError as e:
            self.error(
                f"Error processing JSON response from Chaos projectdiscovery: {e}"
            )

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                "You enabled GO_projectdiscovery but did not set an API key!"
            )
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName not in self.watchedEvents():
            return

        result = self.query(eventData)
        if result is None:
            return

        subdomains = result.get("subdomains")
        if not isinstance(subdomains, list):
            return

        evt = GhostOsintEvent("RAW_RIR_DATA", str(result), self.__name__, event)
        self.notifyListeners(evt)

        resultsSet = set()
        for subdomain in subdomains:
            if self.checkForStop():
                return

            if subdomain in resultsSet:
                continue
            completeSubdomain = f"{subdomain}.{eventData}"
            if self.opts["verify"] and not self.GhostOsint.resolveHost(completeSubdomain) and not self.GhostOsint.resolveHost6(completeSubdomain):
                self.debug(f"Host {completeSubdomain} could not be resolved")
                evt = GhostOsintEvent(
                    "INTERNET_NAME_UNRESOLVED", completeSubdomain, self.__name__, event
                )
                self.notifyListeners(evt)
            else:
                evt = GhostOsintEvent(
                    "INTERNET_NAME", completeSubdomain, self.__name__, event
                )
                self.notifyListeners(evt)

            resultsSet.add(subdomain)

# End of GO_projectdiscovery class
