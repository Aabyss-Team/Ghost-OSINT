# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_dnsdb
# Purpose:     GhostOSINT plug-in that resolves and gets history of domains and IPs
#
# Author:      Filip Aleksić <faleksicdev@gmail.com>
#
# Created:     2020-09-09
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import time

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_dnsdb(GhostOsintPlugin):
    meta = {
        "name": "DNSDB",
        "summary": "查询 FarSight 的 DNSDB 以获取历史记录和 被动查询DNS 数据.",
        'flags': ["apikey"],
        "useCases": ["Passive", "Footprint", "Investigate"],
        "categories": ["Passive DNS"],
        "dataSource": {
            "website": "https://www.farsightsecurity.com",
            "model": "FREE_AUTH_LIMITED",
            "references": [
                "https://docs.dnsdb.info/dnsdb-apiv2/",
                "https://www.farsightsecurity.com/get-started/"
                "https://www.farsightsecurity.com/solutions/dnsdb/",
            ],
            "apiKeyInstructions": [
                "访问 https://www.farsightsecurity.com/get-started/",
                "选择最适合您需求的型号（免费或高级）",
                "填写表单以获取API密钥",
                "检查您的电子邮件以获取API密钥 ",
            ],
            "favIcon": "https://www.farsightsecurity.com/favicon.ico",
            "logo": "https://www.farsightsecurity.com/assets/media/svg/farsight-logo.svg",
            "description": "Farsight Security 的 DNSDB 世界上最大的DNS解析和更改数据数据库."
            "从2010年开始实时更新，DNSDB提供了世界范围内最全面的域名和 IP地址 历史记录.",
        },
    }

    opts = {
        "api_key": "",
        "age_limit_days": 0,
        "verify": True,
        "cohostsamedomain": False,
        "maxcohost": 100,
    }

    optdescs = {
        "api_key": "DNSDB API 密钥.",
        "age_limit_days": "忽略该天数前的DNSDB记录. 0 = 无限.",
        "verify": "通过检查共享主机是否仍解析为共享IP地址来验证它们是否有效.",
        "cohostsamedomain": "将同一目标域上的托管站点视为共同托管?",
        "maxcohost": "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的.",
    }

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS", "DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return [
            "RAW_RIR_DATA",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "PROVIDER_DNS",
            "DNS_TEXT",
            "PROVIDER_MAIL",
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "CO_HOSTED_SITE",
        ]

    def query(self, endpoint, queryType, query):
        if endpoint not in ("rrset", "rdata"):
            self.error(f"Endpoint MUST be rrset or rdata, you sent {endpoint}")
            return None

        if queryType not in ("name", "ip"):
            self.error(f"Query type MUST be name or ip, you sent {queryType}")
            return None

        headers = {"Accept": "application/x-ndjson", "X-API-Key": self.opts["api_key"]}

        res = self.GhostOsint.fetchUrl(
            f"https://api.dnsdb.info/dnsdb/v2/lookup/{endpoint}/{queryType}/{query}",
            timeout=30,
            useragent="GhostOSINT",
            headers=headers,
        )

        if res["code"] == "429":
            self.error("You are being rate-limited by DNSDB")
            self.errorState = True
            return None

        if res["content"] is None:
            self.info(f"No DNSDB record found for {query}")
            return None

        splittedContent = res["content"].strip().split("\n")
        if len(splittedContent) == 2:
            self.info(f"No DNSDB record found for {query}")
            return None

        if len(splittedContent) < 2:
            self.info(f"Unexpected DNSDB response {query}")
            return None

        try:
            records = []
            for content in splittedContent:
                records.append(json.loads(content))
        except json.JSONDecodeError as e:
            self.error(f"Error processing JSON response from DNSDB: {e}")
            return None

        return records[1:-1]

    def isTooOld(self, lastSeen):
        ageLimitTs = int(time.time()) - (86400 * self.opts["age_limit_days"])
        if self.opts["age_limit_days"] > 0 and lastSeen < ageLimitTs:
            self.debug("Record found but too old, skipping.")
            return True
        return False

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error("You enabled GO_dnsdb but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return
        self.results[eventData] = True

        responseData = set()
        coHosts = set()

        if eventName == "DOMAIN_NAME":
            rrsetRecords = self.query("rrset", "name", eventData)
            if rrsetRecords is None:
                return

            evt = GhostOsintEvent("RAW_RIR_DATA", str(rrsetRecords), self.__name__, event)
            self.notifyListeners(evt)

            for record in rrsetRecords:
                record = record.get("obj")
                if self.checkForStop():
                    return

                if self.isTooOld(record.get("time_last", 0)):
                    continue

                if record.get("rrtype") not in (
                    "A",
                    "AAAA",
                    "MX",
                    "NS",
                    "TXT",
                    "CNAME",
                ):
                    continue

                for data in record.get("rdata"):
                    data = data.rstrip(".")
                    if data in responseData:
                        continue
                    responseData.add(data)

                    if record.get("rrtype") == "A":
                        if not self.GhostOsint.validIP(data):
                            self.debug(f"Skipping invalid IP address {data}")
                            continue

                        if self.opts["verify"] and not self.GhostOsint.validateIP(
                            eventData, data
                        ):
                            self.debug(
                                f"Host {eventData} no longer resolves to {data}"
                            )
                            continue

                        evt = GhostOsintEvent("IP_ADDRESS", data, self.__name__, event)

                    if record.get("rrtype") == "AAAA":

                        if not self.getTarget().matches(
                            data, includeChildren=True, includeParents=True
                        ):
                            continue

                        if not self.GhostOsint.validIP6(data):
                            self.debug("Skipping invalid IPv6 address " + data)
                            continue

                        if self.opts["verify"] and not self.GhostOsint.validateIP(
                            eventData, data
                        ):
                            self.debug(
                                "Host " + eventData + " no longer resolves to " + data
                            )
                            continue

                        evt = GhostOsintEvent("IPV6_ADDRESS", data, self.__name__, event)
                    elif record.get("rrtype") == "MX":
                        data = re.sub(r'.*\s+(.*)', r'\1', data)
                        evt = GhostOsintEvent("PROVIDER_MAIL", data, self.__name__, event)
                    elif record.get("rrtype") == "NS":
                        evt = GhostOsintEvent("PROVIDER_DNS", data, self.__name__, event)
                    elif record.get("rrtype") == "TXT":
                        data = data.replace('"', '')
                        evt = GhostOsintEvent("DNS_TEXT", data, self.__name__, event)
                    elif record.get("rrtype") == "CNAME":
                        if not self.getTarget().matches(data):
                            coHosts.add(data)

                    self.notifyListeners(evt)

            rdataRecords = self.query("rdata", "name", eventData)

            if rdataRecords is None:
                return

            evt = GhostOsintEvent("RAW_RIR_DATA", str(rdataRecords), self.__name__, event)
            self.notifyListeners(evt)

            for record in rdataRecords:
                record = record.get("obj")
                if self.isTooOld(record.get("time_last", 0)):
                    continue

                if record.get("rrtype") not in ("NS", "CNAME"):
                    continue
                data = record.get("rrname").rstrip(".")

                if data in responseData:
                    continue
                responseData.add(data)
                if record.get("rrtype") == "NS":
                    evt = GhostOsintEvent("PROVIDER_DNS", data, self.__name__, event)
                elif record.get("rrtype") == "CNAME":
                    if not self.getTarget().matches(data):
                        coHosts.add(data)

        elif eventName in ("IP_ADDRESS", "IPV6_ADDRESS"):
            rdataRecords = self.query("rdata", "ip", eventData)
            if rdataRecords is None:
                return

            evt = GhostOsintEvent("RAW_RIR_DATA", str(rdataRecords), self.__name__, event)
            self.notifyListeners(evt)

            for record in rdataRecords:
                record = record.get("obj")
                if self.checkForStop():
                    return

                if self.isTooOld(record.get("time_last", 0)):
                    continue

                if record.get("rrtype") not in ("A", "AAAA"):
                    continue

                data = record.get("rrname").rstrip(".")

                if data in responseData:
                    continue
                responseData.add(data)

                if not self.getTarget().matches(data):
                    coHosts.add(data)
                    continue

                if self.opts["verify"] and not self.GhostOsint.resolveHost(data) and not self.GhostOsint.resolveHost6(data):
                    self.debug(f"Host {data} could not be resolved")
                    evt = GhostOsintEvent("INTERNET_NAME_UNRESOLVED", data, self.__name__, event)
                else:
                    evt = GhostOsintEvent("INTERNET_NAME", data, self.__name__, event)
                self.notifyListeners(evt)

        for co in coHosts:
            if eventName == "IP_ADDRESS" and (
                self.opts["verify"] and not self.GhostOsint.validateIP(co, eventData)
            ):
                self.debug("Host no longer resolves to our IP.")
                continue

            if not self.opts["cohostsamedomain"]:
                if self.getTarget().matches(co, includeParents=True):
                    self.debug(
                        "Skipping " + co + " because it is on the same domain."
                    )
                    continue

            if self.cohostcount < self.opts["maxcohost"]:
                evt = GhostOsintEvent("CO_HOSTED_SITE", co, self.__name__, event)
                self.notifyListeners(evt)
                self.cohostcount += 1

# End of GO_dnsdb class
