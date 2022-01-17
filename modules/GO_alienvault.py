# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_alienvault
# Purpose:      Query AlienVault OTX
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     14/07/2019
# Copyright:   (c) Steve Micallef 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_alienvault(GhostOsintPlugin):

    meta = {
        'name': "AlienVault 检查",
        'summary': "从 AlienVault 开放威胁平台(OTX) 获取目标信息",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://otx.alienvault.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://otx.alienvault.com/faq",
                "https://otx.alienvault.com/api",
                "https://otx.alienvault.com/submissions/list",
                "https://otx.alienvault.com/pulse/create",
                "https://otx.alienvault.com/endpoint-security/welcome",
                "https://otx.alienvault.com/browse/"
            ],
            'apiKeyInstructions': [
                "访问 https://otx.alienvault.com/",
                "注册一个免费账户",
                "导航到 https://otx.alienvault.com/settings",
                "API密钥将在 'OTX Key'"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://otx.alienvault.com/",
            'logo': "https://otx.alienvault.com/assets/images/otx-logo.svg",
            'description': "世界上第一个真正的开放威胁情报社区\n"
            "开放威胁情报是全球情报监视. "
            "它使私人公司、独立安全研究人员和政府机构能够公开协作并共享有关新出现的威胁、攻击方法和恶意行为者的最新信息，从而提高整个社区的安全性. \n "
            "OTX改变了情报界创建和使用威胁数据的方式. "
            "在OTX中，安全社区中的任何人都可以贡献、讨论、研究、验证, "
            "和共享威胁数据. 您可以直接集成社区生成的OTX威胁数据 "
            "进入您的 AlienVault 和第三方安全产品，让您的威胁检测防御 "
            "始终掌握最新的威胁情报. "
            "今天，140个国家的10万名参与者每天提供1900多万个威胁情报."
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "verify": True,
        "reputation_age_limit_days": 30,
        "cohost_age_limit_days": 30,
        "threat_score_min": 2,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        'subnetlookup': True,
        'maxsubnet': 24,
        'maxv6subnet': 120,
        'max_pages': 50,
        'maxcohost': 100,
        'checkaffiliates': True
    }

    # Option descriptions
    optdescs = {
        "api_key": "AlienVault 开放威胁情报平台 API 密钥.",
        "verify": "通过检查共同主机是否仍解析为共享 IP 地址，验证共同主机是否有效.",
        "reputation_age_limit_days": "忽略此天数前的信誉记录. 0 为无限.",
        "cohost_age_limit_days": "忽略任何超过此天数的共享主机. 0 为无限.",
        "threat_score_min": "最低 AlienVault 威胁评分.",
        'netblocklookup': "在被视为您目标所有子网上查找同一目标子域或域上可能被列入黑名单的主机所有 IP 地址?",
        'maxnetblock': "如果查询网段则设置网段最小的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxv6netblock': "如果查询IPV6网段则设置网段最小的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'subnetlookup': "查找目标子网上的所有IP地址是否在黑名单中?",
        'maxsubnet': "如果查询网段则设置网段最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxv6subnet': "如果查询IPV6网段则设置网段最大的子网划分 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'max_pages': "提取Url地址结果的最大页数.",
        'maxcohost': "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的.",
        'checkaffiliates': "检查关联公司?"
    }

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "INTERNET_NAME",
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "NETBLOCK_OWNER",
            "NETBLOCK_MEMBER",
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "CO_HOSTED_SITE",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "LINKED_URL_INTERNAL"
        ]

    # Parse API response
    def parseAPIResponse(self, res):
        # Future proofing - AlienVault OTX does not implement rate limiting
        if res['code'] == '429':
            self.error("You are being rate-limited by AienVault OTX")
            self.errorState = True
            return None

        if res['code'] == "403":
            self.error("AlienVault OTX API key seems to have been rejected or you have exceeded usage limits for the month.")
            self.errorState = True
            return None

        if res['content'] is None or res['code'] == "404":
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from AlienVault OTX: {e}")

        return None

    def queryReputation(self, qry):
        if ":" in qry:
            target_type = "IPv6"
        elif self.GhostOsint.validIP(qry):
            target_type = "IPv4"
        else:
            self.info(f"Could not determine target type for {qry}")
            return None

        headers = {
            'Accept': 'application/json',
            'X-OTX-API-KEY': self.opts['api_key']
        }

        res = self.GhostOsint.fetchUrl(
            f"https://otx.alienvault.com/api/v1/indicators/{target_type}/{qry}/reputation",
            timeout=self.opts['_fetchtimeout'],
            useragent="GhostOSINT",
            headers=headers)

        return self.parseAPIResponse(res)

    def queryPassiveDns(self, qry):
        if ":" in qry:
            target_type = "IPv6"
        elif self.GhostOsint.validIP(qry):
            target_type = "IPv4"
        else:
            self.info(f"Could not determine target type for {qry}")
            return None

        headers = {
            'Accept': 'application/json',
            'X-OTX-API-KEY': self.opts['api_key']
        }

        res = self.GhostOsint.fetchUrl(
            f"https://otx.alienvault.com/api/v1/indicators/{target_type}/{qry}/passive_dns",
            timeout=self.opts['_fetchtimeout'],
            useragent="GhostOSINT",
            headers=headers)

        return self.parseAPIResponse(res)

    def queryDomainUrlList(self, qry, page=1, per_page=50):
        params = urllib.parse.urlencode({
            'page': page,
            'limit': per_page
        })

        headers = {
            'Accept': 'application/json',
            'X-OTX-API-KEY': self.opts['api_key']
        }
        res = self.GhostOsint.fetchUrl(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{qry}/url_list?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent="GhostOSINT",
            headers=headers)

        return self.parseAPIResponse(res)

    def queryHostnameUrlList(self, qry, page=1, per_page=50):
        params = urllib.parse.urlencode({
            'page': page,
            'limit': per_page
        })

        headers = {
            'Accept': 'application/json',
            'X-OTX-API-KEY': self.opts['api_key']
        }
        res = self.GhostOsint.fetchUrl(
            f"https://otx.alienvault.com/api/v1/indicators/hostname/{qry}/url_list?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent="GhostOSINT",
            headers=headers)

        return self.parseAPIResponse(res)

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error(f"You enabled {self.__class__.__name__} but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return

        if eventName == 'INTERNET_NAME':
            urls = list()
            page = 1
            while page <= self.opts['max_pages']:
                if self.checkForStop():
                    break
                if self.errorState:
                    break

                data = self.queryHostnameUrlList(eventData, page=page)
                page += 1

                url_list = data.get('url_list')
                if not url_list:
                    break

                for url in url_list:
                    u = url.get('url')
                    if not u:
                        continue
                    urls.append(u)

                if not data.get('has_next'):
                    break

            if self.GhostOsint.isDomain(eventData, self.opts['_internettlds']):
                page = 1
                while page <= self.opts['max_pages']:
                    if self.checkForStop():
                        break
                    if self.errorState:
                        break

                    data = self.queryDomainUrlList(eventData, page=page)
                    page += 1

                    url_list = data.get('url_list')
                    if not url_list:
                        break

                    for url in url_list:
                        u = url.get('url')
                        if not u:
                            continue
                        urls.append(u)

                    if not data.get('has_next'):
                        break

            for url in set(urls):
                if not url:
                    continue

                host = self.GhostOsint.urlFQDN(url.lower())

                if not self.getTarget().matches(host, includeChildren=True, includeParents=True):
                    continue

                if url not in self.results:
                    self.results[url] = True
                    evt = GhostOsintEvent('LINKED_URL_INTERNAL', url, self.__name__, event)
                    self.notifyListeners(evt)

            return

        if eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts['netblocklookup']:
                return

            if eventName == 'NETBLOCKV6_OWNER':
                max_netblock = self.opts['maxv6netblock']
            else:
                max_netblock = self.opts['maxnetblock']

            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

        if eventName in ['NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            if not self.opts['subnetlookup']:
                return

            if eventName == 'NETBLOCKV6_MEMBER':
                max_subnet = self.opts['maxv6subnet']
            else:
                max_subnet = self.opts['maxsubnet']

            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

        qrylist = list()
        if eventName.startswith("NETBLOCK"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        # For IP addresses, do the additional passive DNS lookup
        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            ret = self.queryPassiveDns(eventData)

            if ret is None:
                self.info(f"No Passive DNS info for {eventData}")
            else:
                passive_dns = ret.get('passive_dns')
                if passive_dns:
                    self.debug(f"Found passive DNS results for {eventData} in AlienVault OTX")
                    for rec in passive_dns:
                        host = rec.get('hostname')

                        if not host:
                            continue

                        if self.getTarget().matches(host, includeParents=True):
                            evtType = "INTERNET_NAME"
                            if not self.GhostOsint.resolveHost(host) and not self.GhostOsint.resolveHost6(host):
                                evtType = "INTERNET_NAME_UNRESOVLED"
                            evt = GhostOsintEvent(evtType, host, self.__name__, event)
                            self.notifyListeners(evt)
                            continue

                        if self.opts['cohost_age_limit_days'] > 0:
                            try:
                                last = rec.get("last", "")
                                last_dt = datetime.strptime(last, '%Y-%m-%dT%H:%M:%S')
                                last_ts = int(time.mktime(last_dt.timetuple()))
                                age_limit_ts = int(time.time()) - (86400 * self.opts['cohost_age_limit_days'])
                                if last_ts < age_limit_ts:
                                    self.debug(f"Passive DNS record {host} found for {eventData} is too old ({last_dt}), skipping.")
                                    continue
                            except Exception:
                                self.info("Could not parse date from AlienVault data, so ignoring cohost_age_limit_days")

                        if self.opts["verify"] and not self.GhostOsint.validateIP(host, eventData):
                            self.debug(f"Co-host {host} no longer resolves to {eventData}, skipping")
                            continue

                        if self.cohostcount < self.opts['maxcohost']:
                            e = GhostOsintEvent("CO_HOSTED_SITE", host, self.__name__, event)
                            self.notifyListeners(e)
                            self.cohostcount += 1
                        else:
                            self.info(f"Maximum co-host threshold exceeded ({self.opts['maxcohost']}), ignoring co-host {host}")

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS', 'NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            evtType = 'MALICIOUS_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS', 'NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        elif eventName == "INTERNET_NAME":
            evtType = 'MALICIOUS_INTERNET_NAME'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        for addr in qrylist:
            if self.checkForStop():
                return
            if self.errorState:
                return

            rec = self.queryReputation(addr)

            if not rec:
                continue

            if rec.get("reputation", None):
                self.debug(f"Found reputation info for {addr} in AlienVault OTX")
                rec_history = rec['reputation'].get("activities", list())
                threat_score = rec['reputation']['threat_score']
                threat_score_min = self.opts['threat_score_min']

                if threat_score < threat_score_min:
                    self.debug(f"Threat score {threat_score} smaller than {threat_score_min}, skipping.")
                    continue

                descr = f"AlienVault Threat Score: {threat_score}"

                for result in rec_history:
                    nm = result.get("name", None)

                    if nm is None or nm in descr:
                        continue

                    descr += "\n - " + nm
                    created = result.get("last_date", "")
                    if self.opts['reputation_age_limit_days'] > 0:
                        try:
                            # 2014-11-06T10:45:00.000
                            created_dt = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S')
                            created_ts = int(time.mktime(created_dt.timetuple()))
                            age_limit_ts = int(time.time()) - (86400 * self.opts['reputation_age_limit_days'])
                            if created_ts < age_limit_ts:
                                self.debug(f"Reputation record found for {addr} is too old ({created_dt}), skipping.")
                                continue
                        except Exception:
                            self.info("Could not parse date from AlienVault data, so ignoring reputation_age_limit_days")

                # For netblocks, we need to create the IP address event so that
                # the threat intel event is more meaningful.
                if eventName == 'NETBLOCK_OWNER':
                    pevent = GhostOsintEvent("IP_ADDRESS", addr, self.__name__, event)
                    self.notifyListeners(pevent)
                if eventName == 'NETBLOCKV6_OWNER':
                    pevent = GhostOsintEvent("IPV6_ADDRESS", addr, self.__name__, event)
                    self.notifyListeners(pevent)
                elif eventName == 'NETBLOCK_MEMBER':
                    pevent = GhostOsintEvent("AFFILIATE_IPADDR", addr, self.__name__, event)
                    self.notifyListeners(pevent)
                elif eventName == 'NETBLOCKV6_MEMBER':
                    pevent = GhostOsintEvent("AFFILIATE_IPV6_ADDRESS", addr, self.__name__, event)
                    self.notifyListeners(pevent)
                else:
                    pevent = event

                e = GhostOsintEvent(evtType, descr, self.__name__, pevent)
                self.notifyListeners(e)

# End of GO_alienvault class
