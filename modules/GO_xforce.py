# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_xforce
# Purpose:     Obtain IP reputation and passive DNS information from IBM X-Force Exchange.
#
# Author:      Koen Van Impe
#
# Created:     23/12/2015
# Updated:     26/07/2016, Steve Micallef - re-focused to be reputation-centric
# Copyright:   (c) Koen Van Impe
# Licence:     GPL
# -------------------------------------------------------------------------------

import base64
import json
import time
from datetime import datetime

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_xforce(GhostOsintPlugin):

    meta = {
        'name': "XForce Exchange",
        'summary': "从 IBM X-Force Exchange 平台获取 IP地址信誉 和 被动DNS 信息.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://exchange.xforce.ibmcloud.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://api.xforce.ibmcloud.com/doc/",
                "https://exchange.xforce.ibmcloud.com/faq",
            ],
            'apiKeyInstructions': [
                "访问 https://exchange.xforce.ibmcloud.com",
                "注册一个免费账户",
                "导航到 https://exchange.xforce.ibmcloud.com/settings",
                "点击 'API Access'",
                "提供一个 API 名称，然后单击 'Generate'",
                "API 密钥组合列在 'API Key' 和 'API Password'"
            ],
            'favIcon': "https://exchange.xforce.ibmcloud.com/images/shortcut-icons/apple-icon-57x57.png",
            'logo': "https://exchange.xforce.ibmcloud.com/images/shortcut-icons/apple-icon-57x57.png",
            'description': "IBM® X-Force Exchange 是一个基于云的威胁情报共享平台，"
            "可用于快速研究最新的全球安全威胁、聚合可采取行动的情报、咨询专家和与同行协作. "
            "IBM X-Force Exchange, 由人工和机器生成的智能支持，利用 IBM X-Force 的规模帮助用户领先于新出现的威胁.",
        }
    }

    opts = {
        "xforce_api_key": "",
        "xforce_api_key_password": "",
        "age_limit_days": 30,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        'subnetlookup': True,
        'maxsubnet': 24,
        'maxv6subnet': 120,
        'maxcohost': 100,
        'cohostsamedomain': False,
        'checkaffiliates': True,
        'verify': True,
    }

    optdescs = {
        "xforce_api_key": "X-Force Exchange API 密钥.",
        "xforce_api_key_password": "X-Force Exchange API 密码.",
        "age_limit_days": "忽略该天数之前的任何记录. 0 = 无限.",
        'netblocklookup': "在目标的网段上查找所有 IP 地址，以查找同一目标子域或域上可能被列入黑名单的主机?",
        'maxnetblock': "如果查找网段，则为查找其中所有IP的最大网段的大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxv6netblock': "如果查找拥有的网段，则为查找其中所有IP的最大IPv6网段大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'subnetlookup': "查找目标子网上的所有IP地址是否在黑名单中?",
        'maxsubnet': "如果查询子网则设置子网最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxv6subnet': "如果查找子网，则为用于查找其中所有IP的最大IPv6子网大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxcohost': "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的.",
        "cohostsamedomain": "将同一目标域上的托管站点视为共同托管?",
        'checkaffiliates': "检查关联企业?",
        'verify': "通过检查共享主机是否仍解析为共享IP地址来验证它们是否有效.",
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
        return [
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            'IPV6_ADDRESS',
            'AFFILIATE_IPV6_ADDRESS',
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "DOMAIN_NAME",
            "CO_HOSTED_SITE",
            "RAW_RIR_DATA",
        ]

    def query(self, qry, querytype):
        if querytype not in ["ipr/malware", "ipr/history", "resolve"]:
            querytype = "ipr/malware"

        xforce_url = "https://api.xforce.ibmcloud.com"

        api_key = self.opts['xforce_api_key']
        if type(api_key) == str:
            api_key = api_key.encode('utf-8')
        api_key_password = self.opts['xforce_api_key_password']
        if type(api_key_password) == str:
            api_key_password = api_key_password.encode('utf-8')
        token = base64.b64encode(api_key + ":".encode('utf-8') + api_key_password)
        headers = {
            'Accept': 'application/json',
            'Authorization': "Basic " + token.decode('utf-8')
        }
        url = xforce_url + "/" + querytype + "/" + qry
        res = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent="GhostOSINT", headers=headers)

        return self.parseAPIResponse(res)

    # Parse API Response from X-Force Exchange
    # https://exchange.xforce.ibmcloud.com/api/doc/
    def parseAPIResponse(self, res):
        if res['content'] is None:
            self.info("No X-Force Exchange information found")
            return None

        if res['code'] == '400':
            self.error("Bad request")
            return None

        if res['code'] == '404':
            self.info("No X-Force Exchange information found")
            return None

        if res['code'] == '401':
            self.error("X-Force Exchange API key seems to have been rejected.")
            self.errorState = True
            return None

        if res['code'] == '402':
            self.error("X-Force Exchange monthly quota exceeded")
            self.errorState = True
            return None

        if res['code'] == '403':
            self.error("Access denied")
            self.errorState = True
            return None

        if res['code'] == '429':
            self.error("Rate limit exceeded")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from X-Force Exchange")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from X-Force Exchange: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        infield_sep = " ; "

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if self.opts['xforce_api_key'] == "" or self.opts['xforce_api_key_password'] == "":
            self.error("You enabled GO_xforce but did not set an API key/password!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName in ["IP_ADDRESS", "IPV6_ADDRESS"]:
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            if eventName == 'NETBLOCKV6_MEMBER':
                max_subnet = self.opts['maxv6subnet']
            else:
                max_subnet = self.opts['maxsubnet']

            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            if eventName == 'NETBLOCKV6_OWNER':
                max_netblock = self.opts['maxv6netblock']
            else:
                max_netblock = self.opts['maxnetblock']

            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        qrylist = list()
        if eventName.startswith("NETBLOCK"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            if self.checkForStop():
                return

            rec = self.query(addr, "ipr/history")
            if rec:
                rec_history = rec.get("history", list())
                if len(rec_history) > 0:
                    self.debug(f"Found history results for {addr} in XForce")

                    e = GhostOsintEvent("RAW_RIR_DATA", str(rec_history), self.__name__, event)
                    self.notifyListeners(e)

                    for result in rec_history:
                        created = result.get("created", None)
                        # 2014-11-06T10:45:00.000Z
                        if not created:
                            continue

                        created_dt = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000Z')
                        created_ts = int(time.mktime(created_dt.timetuple()))
                        age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                        if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                            self.debug(f"Record found but too old ({created_dt}), skipping.")
                            continue

                        reason = result.get("reason", "")
                        score = result.get("score", 0)
                        cats = result.get("cats", [])
                        cats_description = " ".join(cats)

                        if int(score) < 2:
                            self.debug(f"Non-malicious results (score: {score} < 2), skipping.")
                            continue

                        entry = infield_sep.join([str(reason), str(score), str(created), cats_description])

                        text = f"{entry}\n<SFURL>https://exchange.xforce.ibmcloud.com/ip/{addr}</SFURL>"
                        e = GhostOsintEvent(malicious_type, text, self.__name__, event)
                        self.notifyListeners(e)
                        e = GhostOsintEvent(blacklist_type, text, self.__name__, event)
                        self.notifyListeners(e)

            rec = self.query(addr, "ipr/malware")
            if rec:
                rec_malware = rec.get("malware", list())
                if len(rec_malware) > 0:
                    self.debug(f"Found malware results for {addr} in XForce")

                    e = GhostOsintEvent("RAW_RIR_DATA", str(rec_malware), self.__name__, event)
                    self.notifyListeners(e)

                    for result in rec_malware:
                        origin = result.get("origin", "")
                        domain = result.get("domain", "")
                        uri = result.get("uri", "")
                        md5 = result.get("md5", "")
                        lastseen = result.get("last", "")
                        firstseen = result.get("first", "")
                        family = result.get("family", [])
                        family_description = " ".join(family)

                        entry = infield_sep.join([str(origin), family_description, str(md5), str(domain), str(uri), str(firstseen), str(lastseen)])

                        last = rec.get("last", None)

                        if not last:
                            continue

                        last_dt = datetime.strptime(last, '%Y-%m-%dT%H:%M:%S.000Z')
                        last_ts = int(time.mktime(last_dt.timetuple()))
                        age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])

                        if self.opts['age_limit_days'] > 0 and last_ts < age_limit_ts:
                            self.debug(f"Record found but too old ({last_dt}), skipping.")
                            continue

                        text = f"{entry}\n<SFURL>https://exchange.xforce.ibmcloud.com/ip/{addr}</SFURL>"
                        e = GhostOsintEvent(malicious_type, text, self.__name__, event)
                        self.notifyListeners(e)
                        e = GhostOsintEvent(blacklist_type, text, self.__name__, event)
                        self.notifyListeners(e)

        # For IP addresses, do the additional passive DNS lookup
        # TODO: Add this to the loop above to support netblocks
        if eventName in ["IP_ADDRESS", "IPV6_ADDRESS"]:
            if self.cohostcount >= self.opts['maxcohost']:
                return

            ret = self.query(eventData, "resolve")
            if not ret:
                self.info(f"No Passive DNS info for {eventData}")
                return

            passive = ret.get('Passive')
            if not passive:
                return

            records = passive.get('records')
            if not records:
                return

            self.debug(f"Found passive DNS results for {eventData} in Xforce")

            e = GhostOsintEvent("RAW_RIR_DATA", str(records), self.__name__, event)
            self.notifyListeners(e)

            for rec in records:
                if self.checkForStop():
                    return

                if rec['recordType'] == "A":
                    last = rec.get("last", None)

                    if not last:
                        continue

                    host = rec.get('value')
                    if not host:
                        continue

                    last_dt = datetime.strptime(last, '%Y-%m-%dT%H:%M:%SZ')
                    last_ts = int(time.mktime(last_dt.timetuple()))
                    age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])

                    if self.opts['verify']:
                        if not self.GhostOsint.validateIP(host, eventData):
                            self.debug(f"Host {host} no longer resolves to {eventData}")
                            continue
                    else:
                        if self.opts['age_limit_days'] > 0 and last_ts < age_limit_ts:
                            self.debug(f"Record found but too old ({last_dt}), skipping.")
                            continue

                    if not self.opts["cohostsamedomain"]:
                        if self.getTarget().matches(host, includeParents=True):
                            if self.GhostOsint.resolveHost(host) or self.GhostOsint.resolveHost6(host):
                                e = GhostOsintEvent("INTERNET_NAME", host, self.__name__, event)
                            else:
                                e = GhostOsintEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, event)
                            self.notifyListeners(e)

                            if self.GhostOsint.isDomain(host, self.opts['_internettlds']):
                                e = GhostOsintEvent("DOMAIN_NAME", host, self.__name__, event)
                                self.notifyListeners(e)
                            continue

                    e = GhostOsintEvent("CO_HOSTED_SITE", host, self.__name__, event)
                    self.notifyListeners(e)
                    self.cohostcount += 1

# End of GO_xforce class
