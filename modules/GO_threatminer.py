# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_threatminer
# Purpose:      Query ThreatMiner.org using their API.
#
# Author:      Steve Micallef
#
# Created:     12/07/2019
# Copyright:   (c) Steve Micallef 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
from datetime import datetime

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_threatminer(GhostOsintPlugin):

    meta = {
        'name': "ThreatMiner",
        'summary': "从 ThreatMiner 的 被动DNS 和威胁情报数据库中获取信息.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.threatminer.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.threatminer.org/api.php",
                "https://www.threatminer.org/features.php"
            ],
            'favIcon': "https://www.threatminer.org/images/favicon.gif",
            'logo': "https://www.threatminer.org/images/logo.png",
            'description': "ThreatMiner 是一个威胁情报门户，旨在使分析师能够在单一界面下进行研究. "
            "它用于SANS的578网络威胁情报课程.\n"
            "定期对恶意软件和网络基础设施进行研究的威胁情报和入侵分析人员经常发现，需要依赖于多个网站，这些网站各自占据了更大难题的一小部分.",
        }
    }
    # Default options
    opts = {
        'verify': True,
        'netblocklookup': False,
        'maxnetblock': 24,
        'subnetlookup': False,
        'maxsubnet': 24,
        'maxcohost': 100,
        "age_limit_days": 90
    }

    # Option descriptions
    optdescs = {
        'verify': '验证在目标域名上找到的任何主机名是否仍可解析?',
        'netblocklookup': "在目标的网段上查找所有 IP 地址，以查找同一目标子域或域上可能被列入黑名单的主机?",
        'maxnetblock': "如果查找网段，则为查找其中所有IP的最大网段的大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'subnetlookup': "查找目标所属子网上的所有IP地址?",
        'maxsubnet': "如果查询子网则设置子网最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxcohost': "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的.",
        "age_limit_days": "忽略早于此天数的记录. 0为无限."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    cohostcount = 0
    reportedhosts = None
    checkedips = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.reportedhosts = self.tempStorage()
        self.checkedips = self.tempStorage()
        self.cohostcount = 0

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "DOMAIN_NAME", "NETBLOCK_OWNER",
                "NETBLOCK_MEMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "CO_HOSTED_SITE"]

    def query(self, qry, querytype):
        if self.GhostOsint.validIP(qry):
            tgttype = "host"
        else:
            tgttype = "domain"

        if querytype == "subs":
            queryurl = "/v2/" + tgttype + ".php?q={0}&rt=5"
        if querytype == "passive":
            queryurl = "/v2/" + tgttype + ".php?q={0}&rt=2"

        threatminerurl = "https://api.threatminer.org"
        url = threatminerurl + queryurl.format(qry)
        res = self.GhostOsint.fetchUrl(url, timeout=10, useragent="GhostOSINT")

        if res['content'] is None:
            self.info("No ThreatMiner info found for " + qry)
            return None

        if len(res['content']) == 0:
            self.info("No ThreatMiner info found for " + qry)
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from ThreatMiner: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return
            if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                self.debug("Network size bigger than permitted: "
                           + str(IPNetwork(eventData).prefixlen) + " > "
                           + str(self.opts['maxnetblock']))
                return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return
            if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                self.debug("Network size bigger than permitted: "
                           + str(IPNetwork(eventData).prefixlen) + " > "
                           + str(self.opts['maxsubnet']))
                return

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True

        if eventName == "IP_ADDRESS":
            qrylist.append(eventData)

        # qrylist now contains all IPs we want to look up
        for qry in qrylist:
            evtType = "CO_HOSTED_SITE"
            ret = self.query(qry, "passive")
            if ret is None:
                self.info("No Passive DNS info for " + qry)
                return

            if "results" not in ret:
                continue
            if len(ret['results']) == 0:
                continue

            self.debug("Found passive DNS results in ThreatMiner")
            res = ret["results"]
            for rec in res:
                # Skip stuff with no date
                if rec.get('last_seen') == '':
                    continue
                last_seen = datetime.strptime(rec.get('last_seen', "1970-01-01 00:00:00"), '%Y-%m-%d %H:%M:%S')
                last_ts = int(time.mktime(last_seen.timetuple()))
                age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                if self.opts['age_limit_days'] > 0 and last_ts < age_limit_ts:
                    self.debug("Record found but too old, skipping.")
                    continue

                host = rec['domain']
                if host == eventData:
                    continue
                if self.getTarget().matches(host, includeParents=True):
                    if self.opts['verify'] and not self.GhostOsint.resolveHost(host) and not self.GhostOsint.resolveHost6(host):
                        evt = GhostOsintEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, event)
                    else:
                        evt = GhostOsintEvent("INTERNET_NAME", host, self.__name__, event)
                    self.notifyListeners(evt)
                    self.reportedhosts[host] = True
                    continue

                if self.cohostcount < self.opts['maxcohost']:
                    e = GhostOsintEvent(evtType, host, self.__name__, event)
                    self.notifyListeners(e)
                    self.cohostcount += 1

        if eventName == "DOMAIN_NAME":
            evtType = "INTERNET_NAME"
            ret = self.query(eventData, "subs")
            if ret is None:
                self.debug("No hosts found")
                return

            if len(ret.get("results", list())) == 0:
                self.debug("No hosts found")
                return

            for host in ret.get("results"):
                self.debug("Found host results in ThreatMiner")

                if host in self.reportedhosts:
                    continue

                self.reportedhosts[host] = True

                if self.opts['verify'] and not self.GhostOsint.resolveHost(host) and not self.GhostOsint.resolveHost6(host):
                    evt = GhostOsintEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, event)
                else:
                    evt = GhostOsintEvent("INTERNET_NAME", host, self.__name__, event)
                evt = GhostOsintEvent(evtType, host, self.__name__, event)
                self.notifyListeners(evt)

# End of GO_threatminer class
