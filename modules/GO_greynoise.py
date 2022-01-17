# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_greynoise
# Purpose:      Query GreyNoise's API
#
# Author:       Steve Micallef
# Updated By:   Brad Chiappetta, GreyNoise
#
# Created:      20/11/2018
# Updated:      15-Nov-2021
# Copyright:    (c) Steve Micallef
# Licence:      GPL
# -------------------------------------------------------------------------------

import json
import time
from datetime import datetime
from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_greynoise(GhostOsintPlugin):

    meta = {
        "name": "GreyNoise",
        "summary": "从 GreyNoise 中获取IP地址的详细数据",
        "flags": ["apikey"],
        "useCases": ["Investigate", "Passive"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://greynoise.io/",
            "model": "FREE_AUTH_LIMITED",
            "references": ["https://docs.greynoise.io/", "https://www.greynoise.io/viz/signup"],
            "apiKeyInstructions": [
                "访问 https://www.greynoise.io/viz/signup",
                "登录一个免费的账户",
                "导航到 https://www.greynoise.io/viz/account/",
                "API 密钥将在 'API Key'",
            ],
            "favIcon": "https://www.greynoise.io/favicon.ico",
            "logo": "https://www.greynoise.io/_nuxt/img/greynoise-logo.dccd59d.png",
            "description": "在 GreyNoise ，我们收集和分析直接连接到 Internet 的每台服务器的无目标、普遍的随机扫描和攻击活动. "
            "大规模扫描器（如 Shodan 和 Censys ）、搜索引擎、机器人、蠕虫和爬虫程序在IPv4空间中的每个IP地址上全方位生成日志和事件. "
            "GreyNoise 使你能够过滤掉这些无用的干扰.",
        },
    }

    # Default options
    opts = {
        "api_key": "",
        "age_limit_days": 30,
        "netblocklookup": True,
        "maxnetblock": 24,
        "subnetlookup": True,
        "maxsubnet": 24
        # 'asnlookup': True
    }

    # Option descriptions
    optdescs = {
        "api_key": "GreyNoise API 密钥.",
        "age_limit_days": "忽略该天数之前的任何记录. 0 = 无限.",
        "netblocklookup": "在被视为你的目标所有的网段上查找同一目标子域或域名上可能被列入黑名单的主机的所有IP地址?",
        "maxnetblock": "如果查找网段，则为查找其中所有IP的最大网段的大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        "subnetlookup": "查找目标所属的子网以将其列入黑名单?",
        "maxsubnet": "如果查询子网则设置子网最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)"
        # 'asnlookup': "Look up ASNs that your target is a member of?"
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
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "NETBLOCK_MEMBER", "NETBLOCK_OWNER"]

    # What events this module produces
    def producedEvents(self):
        return [
            "MALICIOUS_IPADDR",
            "MALICIOUS_ASN",
            "MALICIOUS_SUBNET",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "COMPANY_NAME",
            "GEOINFO",
            "BGP_AS_MEMBER",
            "OPERATING_SYSTEM",
            "RAW_RIR_DATA",
        ]

    def queryIP(self, qry, qry_type):
        gn_context_url = "https://api.greynoise.io/v2/noise/context/"
        gn_riot_url = "https://api.greynoise.io/v2/riot/"
        gn_gnql_url = "https://api.greynoise.io/v2/experimental/gnql?query="

        headers = {"key": self.opts["api_key"]}
        res = {}
        if qry_type == "ip":
            self.debug(f"Querying GreyNoise for IP: {qry}")
            ip_res = {}
            riot_res = {}
            ip_response = self.GhostOsint.fetchUrl(
                gn_context_url + qry,
                timeout=self.opts["_fetchtimeout"],
                useragent="greynoise-ghostosint-v1.1.0",
                headers=headers,
            )
            if ip_response["code"] == "200":
                ip_res = json.loads(ip_response["content"])
            riot_response = self.GhostOsint.fetchUrl(
                gn_riot_url + qry,
                timeout=self.opts["_fetchtimeout"],
                useragent="greynoise-ghostosint-v1.1.0",
                headers=headers,
            )
            if riot_response["code"] in ["200", "404"]:
                riot_res = json.loads(riot_response["content"])

            if ip_res and not riot_res:
                res = ip_res
            elif riot_res and not ip_res:
                res = riot_res
            else:
                res = ip_res.copy()
                res.update(riot_res)
        else:
            self.debug(f"Querying GreyNoise for Netblock: {qry}")
            query_response = self.GhostOsint.fetchUrl(
                gn_gnql_url + qry,
                timeout=self.opts["_fetchtimeout"],
                useragent="greynoise-ghostosint-v1.1.0",
                headers=headers,
            )
            if query_response["code"] == "200":
                res = json.loads(query_response["content"])

        if not res:
            self.error("Greynoise API key seems to have been rejected or you have exceeded usage limits.")
            self.errorState = True
            return None

        return res

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error("You enabled GO_greynoise but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "NETBLOCK_OWNER":
            if not self.opts["netblocklookup"]:
                return
            else:
                if IPNetwork(eventData).prefixlen < self.opts["maxnetblock"]:
                    self.debug(
                        "Network size bigger than permitted: "
                        + str(IPNetwork(eventData).prefixlen)
                        + " > "
                        + str(self.opts["maxnetblock"])
                    )
                    return

        if eventName == "NETBLOCK_MEMBER":
            if not self.opts["subnetlookup"]:
                return
            else:
                if IPNetwork(eventData).prefixlen < self.opts["maxsubnet"]:
                    self.debug(
                        "Network size bigger than permitted: "
                        + str(IPNetwork(eventData).prefixlen)
                        + " > "
                        + str(self.opts["maxsubnet"])
                    )
                    return

        if eventName == "IP_ADDRESS":
            evtType = "MALICIOUS_IPADDR"
            qryType = "ip"
        if eventName.startswith("NETBLOCK_"):
            evtType = "MALICIOUS_IPADDR"
            qryType = "netblock"
        if eventName == "AFFILIATE_IPADDR":
            evtType = "MALICIOUS_AFFILIATE_IPADDR"
            qryType = "ip"

        ret = self.queryIP(eventData, qryType)

        if not ret:
            return

        if "data" not in ret and "seen" not in ret and "riot" not in ret:
            return

        if "data" in ret and len(ret["data"]) > 0:
            for rec in ret["data"]:
                if rec.get("seen", None):
                    self.debug(f"Found threat info in Greynoise: {rec['ip']}")
                    lastseen = rec.get("last_seen", "1970-01-01")
                    lastseen_dt = datetime.strptime(lastseen, "%Y-%m-%d")
                    lastseen_ts = int(time.mktime(lastseen_dt.timetuple()))
                    age_limit_ts = int(time.time()) - (86400 * self.opts["age_limit_days"])
                    if self.opts["age_limit_days"] > 0 and lastseen_ts < age_limit_ts:
                        self.debug(f"Record [{rec['ip']}] found but too old, skipping.")
                        return

                    # Only report meta data about the target, not affiliates
                    if rec.get("metadata") and eventName == "IP_ADDRESS":
                        met = rec.get("metadata")
                        if met.get("country", "unknown") != "unknown":
                            loc = ""
                            if met.get("city"):
                                loc = met.get("city") + ", "
                            loc += met.get("country")
                            e = GhostOsintEvent("GEOINFO", loc, self.__name__, event)
                            self.notifyListeners(e)
                        if met.get("asn", "unknown") != "unknown":
                            asn = met.get("asn").replace("AS", "")
                            e = GhostOsintEvent("BGP_AS_MEMBER", asn, self.__name__, event)
                            self.notifyListeners(e)
                        if met.get("organization", "unknown") != "unknown":
                            e = GhostOsintEvent("COMPANY_NAME", met.get("organization"), self.__name__, event)
                            self.notifyListeners(e)
                        if met.get("os", "unknown") != "unknown":
                            e = GhostOsintEvent("OPERATING_SYSTEM", met.get("os"), self.__name__, event)
                            self.notifyListeners(e)
                        e = GhostOsintEvent("RAW_RIR_DATA", str(rec), self.__name__, event)
                        self.notifyListeners(e)

                    if rec.get("classification"):
                        descr = (
                            "GreyNoise - Mass-Scanning IP Detected ["
                            + rec.get("ip")
                            + "]\n - Classification: "
                            + rec.get("classification")
                        )
                        if rec.get("tags"):
                            descr += "\n - " + "Scans For Tags: " + ", ".join(rec.get("tags"))
                        if rec.get("cve"):
                            descr += "\n - " + "Scans For CVEs: " + ", ".join(rec.get("cve"))
                        if rec.get("raw_data") and not (rec.get("tags") or ret.get("cve")):
                            descr += "\n - " + "Raw data: " + str(rec.get("raw_data"))
                        descr += "\n<SFURL>https://www.greynoise.io/viz/ip/" + rec.get("ip") + "</SFURL>"
                        e = GhostOsintEvent(evtType, descr, self.__name__, event)
                        self.notifyListeners(e)

        if "seen" in ret:
            if ret.get("seen", None):
                lastseen = ret.get("last_seen", "1970-01-01")
                lastseen_dt = datetime.strptime(lastseen, "%Y-%m-%d")
                lastseen_ts = int(time.mktime(lastseen_dt.timetuple()))
                age_limit_ts = int(time.time()) - (86400 * self.opts["age_limit_days"])
                if self.opts["age_limit_days"] > 0 and lastseen_ts < age_limit_ts:
                    self.debug("Record found but too old, skipping.")
                    return

                # Only report meta data about the target, not affiliates
                if ret.get("metadata") and eventName == "IP_ADDRESS":
                    met = ret.get("metadata")
                    if met.get("country", "unknown") != "unknown":
                        loc = ""
                        if met.get("city"):
                            loc = met.get("city") + ", "
                        loc += met.get("country")
                        e = GhostOsintEvent("GEOINFO", loc, self.__name__, event)
                        self.notifyListeners(e)
                    if met.get("asn", "unknown") != "unknown":
                        asn = met.get("asn").replace("AS", "")
                        e = GhostOsintEvent("BGP_AS_MEMBER", asn, self.__name__, event)
                        self.notifyListeners(e)
                    if met.get("organization", "unknown") != "unknown":
                        e = GhostOsintEvent("COMPANY_NAME", met.get("organization"), self.__name__, event)
                        self.notifyListeners(e)
                    if met.get("os", "unknown") != "unknown":
                        e = GhostOsintEvent("OPERATING_SYSTEM", met.get("os"), self.__name__, event)
                        self.notifyListeners(e)
                    e = GhostOsintEvent("RAW_RIR_DATA", str(ret), self.__name__, event)
                    self.notifyListeners(e)

                if ret.get("classification"):
                    descr = (
                        "GreyNoise - Mass-Scanning IP Detected ["
                        + eventData
                        + "]\n - Classification: "
                        + ret.get("classification")
                    )
                    if ret.get("tags"):
                        descr += "\n - " + "Scans For Tags: " + ", ".join(ret.get("tags"))
                    if ret.get("cve"):
                        descr += "\n - " + "Scans For CVEs: " + ", ".join(ret.get("cve"))
                    if ret.get("raw_data") and not (ret.get("tags") or ret.get("cve")):
                        descr += "\n - " + "Raw data: " + str(ret.get("raw_data"))
                    descr += "\n<SFURL>https://www.greynoise.io/viz/ip/" + ret.get("ip") + "</SFURL>"
                    e = GhostOsintEvent(evtType, descr, self.__name__, event)
                    self.notifyListeners(e)

        if "riot" in ret:
            if ret.get("riot", None):
                lastseen = ret.get("last_updated", "1970-01-01")
                lastseen = lastseen.split("T")[0]
                lastseen_dt = datetime.strptime(lastseen, "%Y-%m-%d")
                lastseen_ts = int(time.mktime(lastseen_dt.timetuple()))
                age_limit_ts = int(time.time()) - (86400 * self.opts["age_limit_days"])
                if self.opts["age_limit_days"] > 0 and lastseen_ts < age_limit_ts:
                    self.debug("Record found but too old, skipping.")
                    return

                if ret.get("trust_level"):
                    descr = (
                        "GreyNoise - Common-Business Service IP Detected ["
                        + eventData
                        + "]\n - Trust Level: "
                        + ret.get("trust_level")
                    )
                    if ret.get("name"):
                        descr += "\n - " + "Provider Name: " + ret.get("name")
                    if ret.get("category"):
                        descr += "\n - " + "Provider Category: " + ret.get("category")
                    descr += "\n<SFURL>https://www.greynoise.io/viz/ip/" + ret.get("ip") + "</SFURL>"
                    e = GhostOsintEvent(evtType, descr, self.__name__, event)
                    self.notifyListeners(e)


# End of GO_greynoise class
