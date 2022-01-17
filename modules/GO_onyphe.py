# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_onyphe
# Purpose:      GhostOSINT plug-in to check if the IP is included on Onyphe
#               data (threat list, geo-location, pastries, vulnerabilities)
#
# Author:      Filip Aleksić <faleksicdev@gmail.com>
#
# Created:     2020-08-21
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
from datetime import datetime

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_onyphe(GhostOsintPlugin):

    meta = {
        "name": "Onyphe",
        "summary": "通过 Onyphe 检查指定的IP地址信息 (威胁列表, 地理位置, 漏洞).",
        'flags': ["apikey"],
        "useCases": ["Footprint", "Passive", "Investigate"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://www.onyphe.io",
            "model": "FREE_AUTH_LIMITED",
            "references": ["https://www.onyphe.io/documentation/api"],
            "apiKeyInstructions": [
                "访问 https://www.onyphe.io/login/#register",
                "注册一个免费账户",
                "你应该在你的电子邮件中收到你的 API 密钥，或者你可以按照后续步骤自行获取",
                "转到账户设置 https://www.onyphe.io/auth/account",
                "API 密钥将在 'API Key'",
            ],
            "favIcon": "https://www.onyphe.io/favicon.ico",
            "logo": "https://www.onyphe.io/img/logo-solo.png",
            "description": "ONYPHE是一个搜索引擎，通过搜索互联网上的各种来源或监听互联网噪音来收集开源和网络威胁情报数据. "
            "嘿，通过我们使用的API使这些数据可用. "
            "我们检查他们的数据以查看关于IP地址的以下信息：地理位置，它是否有一些漏洞，它是否在威胁列表上. ",
        },
    }

    opts = {
        "api_key": "",
        "paid_plan": False,
        "max_page": 10,
        "verify": True,
        "age_limit_days": 30,
        "cohostsamedomain": False,
        "maxcohost": 100,
    }
    optdescs = {
        "api_key": "Onyphe 访问令牌.",
        "paid_plan": "你是否使用付费计划? 付费计划已启用分页",
        "max_page": "要循环访问的最大页数. Onyphe最多有1000页(10，000个结果). 只对付费计划有影响",
        "verify": "验证标识的域名是否仍解析为关联的指定IP地址.",
        "age_limit_days": "忽略该天数之前的任何记录. 0 = 无限.",
        "maxcohost": "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的.",
        "cohostsamedomain": "将同一目标域上的托管站点视为共同托管?",
    }

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS"]

    # What events this module produces
    def producedEvents(self):
        return [
            "GEOINFO",
            "MALICIOUS_IPADDR",
            "LEAKSITE_CONTENT",
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "VULNERABILITY_GENERAL",
            "RAW_RIR_DATA",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "PHYSICAL_COORDINATES",
        ]

    def query(self, endpoint, ip, page=1):
        retarr = list()

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"apikey {self.opts['api_key']}",
        }
        res = self.GhostOsint.fetchUrl(
            f"https://www.onyphe.io/api/v2/simple/{endpoint}/{ip}?page={page}",
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts["_useragent"],
            headers=headers,
        )

        if res["code"] == "429":
            self.error("Reaching rate limit on Onyphe API")
            self.errorState = True
            return None

        if res["code"] == 400:
            self.error("Invalid request or API key on Onyphe")
            self.errorState = True
            return None

        try:
            info = json.loads(res["content"])
            if "status" in info and info["status"] == "nok":
                self.error(
                    f"Unexpected error happened while requesting data from Onyphe. Error message: {info.get('text', '')}"
                )
                self.errorState = True
                return None
            elif "results" not in info or info["results"] == []:
                self.info(f"No Onyphe {endpoint} data found for {ip}")
                return None
        except Exception as e:
            self.debug(f"{e.__class__} {res['code']} {res['content']}")
            self.error("Error processing JSON response from Onyphe.")
            return None

        # Go through other pages if user has paid plan
        try:
            current_page = int(info["page"])
            if (
                self.opts["paid_plan"]
                and info.get("page")
                and int(info.get("max_page")) > current_page
            ):
                page = current_page + 1

                if page > self.opts["max_page"]:
                    self.error(
                        "Maximum number of pages from options for Onyphe reached."
                    )
                    return [info]
                retarr.append(info)
                response = self.query(endpoint, ip, page)
                if response:
                    retarr.extend(response)
            else:
                retarr.append(info)

        except ValueError:
            self.error(
                f"Unexpected value for page in response from Onyphe, url: https://www.onyphe.io/api/v2/simple/{endpoint}/{ip}?page={page}"
            )
            self.errorState = True
            return None

        return retarr

    def emitLocationEvent(self, location, eventData, event):
        if location is None:
            return
        self.info(f"Found location for {eventData}: {location}")

        evt = GhostOsintEvent("PHYSICAL_COORDINATES", location, self.__name__, event)
        self.notifyListeners(evt)

    def emitDomainData(self, response, eventData, event):
        domains = set()
        if response.get("domain") is not None and isinstance(
            response['domain'], list
        ):
            for dom in response['domain']:
                domains.add(dom)

        if response.get("subdomains") is not None and isinstance(
            response["subdomains"], list
        ):
            for subDomain in response["subdomains"]:
                domains.add(subDomain)

        for domain in domains:
            if self.getTarget().matches(domain):
                if self.opts['verify']:
                    if self.GhostOsint.resolveHost(domain) or self.GhostOsint.resolveHost6(domain):
                        evt = GhostOsintEvent('INTERNET_NAME', domain, self.__name__, event)
                    else:
                        evt = GhostOsintEvent('INTERNET_NAME_UNRESOLVED', domain, self.__name__, event)
                    self.notifyListeners(evt)

                if self.GhostOsint.isDomain(domain, self.opts['_internettlds']):
                    evt = GhostOsintEvent('DOMAIN_NAME', domain, self.__name__, event)
                    self.notifyListeners(evt)
                continue

            if self.cohostcount < self.opts['maxcohost']:
                if self.opts["verify"] and not self.GhostOsint.validateIP(domain, eventData):
                    self.debug("Host no longer resolves to our IP.")
                    continue

                if not self.opts["cohostsamedomain"]:
                    if self.getTarget().matches(domain, includeParents=True):
                        self.debug(
                            "Skipping " + domain + " because it is on the same domain."
                        )
                        continue

                evt = GhostOsintEvent("CO_HOSTED_SITE", domain, self.__name__, event)
                self.notifyListeners(evt)
                self.cohostcount += 1

    def isFreshEnough(self, result):
        limit = self.opts["age_limit_days"]
        if limit <= 0:
            return True

        timestamp = result.get("@timestamp")
        if timestamp is None:
            self.debug("Record doesn't have timestamp defined")
            return False

        last_dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        last_ts = int(time.mktime(last_dt.timetuple()))
        age_limit_ts = int(time.time()) - (86400 * limit)

        if last_ts < age_limit_ts:
            self.debug("Record found but too old, skipping.")
            return False

        return True

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        sentData = set()

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error("You enabled GO_onyphe, but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug("Skipping " + eventData + " as already mapped.")
            return

        self.results[eventData] = True

        geoLocDataArr = self.query("geoloc", eventData)

        if geoLocDataArr is not None:
            evt = GhostOsintEvent(
                "RAW_RIR_DATA", str(geoLocDataArr), self.__name__, event
            )
            self.notifyListeners(evt)

            for geoLocData in geoLocDataArr:
                if self.checkForStop():
                    return

                for result in geoLocData["results"]:
                    if not self.isFreshEnough(result):
                        continue

                    location = ", ".join(
                        [
                            _f
                            for _f in [
                                result.get("city"),
                                result.get("country"),
                            ]
                            if _f
                        ]
                    )
                    self.info("Found GeoIP for " + eventData + ": " + location)

                    if location in sentData:
                        self.debug(f"Skipping {location}, already sent")
                        continue

                    sentData.add(location)

                    evt = GhostOsintEvent("GEOINFO", location, self.__name__, event)
                    self.notifyListeners(evt)

                    coordinates = result.get("location")
                    if coordinates is None:
                        continue

                    if coordinates in sentData:
                        self.debug(f"Skipping {coordinates}, already sent")
                        continue
                    sentData.add(coordinates)

                    self.emitLocationEvent(coordinates, eventData, event)

                    self.emitDomainData(result, eventData, event)

        pastriesDataArr = self.query("pastries", eventData)

        if pastriesDataArr is not None:
            evt = GhostOsintEvent(
                "RAW_RIR_DATA", str(pastriesDataArr), self.__name__, event
            )
            self.notifyListeners(evt)

            for pastriesData in pastriesDataArr:
                if self.checkForStop():
                    return

                for result in pastriesData["results"]:
                    pastry = result.get("content")
                    if pastry is None:
                        continue

                    if pastry in sentData:
                        self.debug(f"Skipping {pastry}, already sent")
                        continue
                    sentData.add(pastry)

                    if not self.isFreshEnough(result):
                        continue

                    evt = GhostOsintEvent(
                        "LEAKSITE_CONTENT", pastry, self.__name__, event
                    )
                    self.notifyListeners(evt)

        threatListDataArr = self.query("threatlist", eventData)

        if threatListDataArr is not None:
            evt = GhostOsintEvent(
                "RAW_RIR_DATA", str(threatListDataArr), self.__name__, event
            )
            self.notifyListeners(evt)

            for threatListData in threatListDataArr:
                if self.checkForStop():
                    return

                for result in threatListData["results"]:
                    threatList = result.get("threatlist")

                    if threatList is None:
                        continue

                    if threatList in sentData:
                        self.debug(f"Skipping {threatList}, already sent")
                        continue
                    sentData.add(threatList)

                    if not self.isFreshEnough(result):
                        continue

                    evt = GhostOsintEvent(
                        "MALICIOUS_IPADDR",
                        result.get("threatlist"),
                        self.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

        vulnerabilityDataArr = self.query("vulnscan", eventData)

        if vulnerabilityDataArr is not None:
            evt = GhostOsintEvent(
                "RAW_RIR_DATA", str(vulnerabilityDataArr), self.__name__, event
            )
            self.notifyListeners(evt)

            for vulnerabilityData in vulnerabilityDataArr:
                if self.checkForStop():
                    return

                for result in vulnerabilityData["results"]:
                    if not self.isFreshEnough(result):
                        continue

                    cves = result.get("cve")

                    if cves is None:
                        continue

                    for cve in cves:
                        if not cve:
                            continue

                        if cve in sentData:
                            continue
                        sentData.add(cve)

                        etype, cvetext = self.GhostOsint.cveInfo(cve)
                        evt = GhostOsintEvent(
                            etype,
                            cvetext,
                            self.__name__,
                            event,
                        )
                        self.notifyListeners(evt)

# End of GO_onyphe class
