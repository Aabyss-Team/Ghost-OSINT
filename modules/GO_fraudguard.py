# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_fraudguard
# Purpose:      Query fraudguard.io using their API
#
# Author:      Steve Micallef
#
# Created:     18/06/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import base64
import json
import time
from datetime import datetime

from netaddr import IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_fraudguard(GhostOsintPlugin):

    meta = {
        'name': "Fraudguard",
        'summary': "从 Fraudguard.io 获取威胁情报",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://fraudguard.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.fraudguard.io/",
                "https://faq.fraudguard.io/"
            ],
            'apiKeyInstructions': [
                "访问 https://app.fraudguard.io/register",
                "注册一个免费账户",
                "导航到 https://app.fraudguard.io/keys",
                "API 密钥将显示在用户名和密码下"
            ],
            'favIcon': "https://fraudguard.io/img/favicon.ico",
            'logo': "https://s3.amazonaws.com/fraudguard.io/img/header.png",
            'description': "FraudGuard是一项服务，旨在通过不断收集和分析实时互联网流量，提供一种简单的方法来验证使用情况. "
            "我们仅利用几个简单的API端点，使集成尽可能简单，并返回数据，如：风险级别、威胁类型、地理位置等.\n"
            "超快速，超简单。通过查询我们的威胁引擎查找任何IP地址.",
        }
    }

    # Default options
    opts = {
        "fraudguard_api_key_account": "",
        "fraudguard_api_key_password": "",
        "age_limit_days": 90,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        'subnetlookup': True,
        'maxsubnet': 24,
        'maxv6subnet': 120,
        'checkaffiliates': True
    }

    # Option descriptions
    optdescs = {
        "fraudguard_api_key_account": "Fraudguard.io API 用户名.",
        "fraudguard_api_key_password": "Fraudguard.io API 密码.",
        "age_limit_days": "忽略该天数之前的任何记录. 0 = 无限.",
        'netblocklookup': "在目标的网段上查找所有 IP 地址，以查找同一目标子域或域上可能被列入黑名单的主机?",
        'maxnetblock': "如果查找拥有的网段，则为查找其中所有IP的最大网段大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxv6netblock': "如果查找拥有的网段，则为查找其中所有IP的最大IPv6网段大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'subnetlookup': "查找目标子网上的所有IP地址是否在黑名单中?",
        'maxsubnet': "如果查找子网，则为用于查找其中所有IP的最大IPv4子网大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'maxv6subnet': "如果查找子网，则为用于查找其中所有IP的最大IPv6子网大小 (CIDR 值, 24 = /24, 16 = /16, 等等.)",
        'checkaffiliates': "检查关联企业?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.errorState = False
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
        ]

    def producedEvents(self):
        return [
            "GEOINFO",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_SUBNET",
            "MALICIOUS_NETBLOCK"
        ]

    def query(self, qry):
        """Query IP address

        Args:
            qry (str): IPv4/IPv6 address

        Returns:
            dict: JSON formatted results
        """

        fraudguard_url = "https://api.fraudguard.io/ip/" + qry
        api_key_account = self.opts['fraudguard_api_key_account']
        if type(api_key_account) == str:
            api_key_account = api_key_account.encode('utf-8')
        api_key_password = self.opts['fraudguard_api_key_password']
        if type(api_key_password) == str:
            api_key_password = api_key_password.encode('utf-8')
        token = base64.b64encode(api_key_account + ':'.encode('utf-8') + api_key_password)
        headers = {
            'Authorization': "Basic " + token.decode('utf-8')
        }

        res = self.GhostOsint.fetchUrl(
            fraudguard_url,
            timeout=self.opts['_fetchtimeout'],
            useragent="GhostOSINT",
            headers=headers
        )

        if res['code'] in ["400", "429", "500", "403"]:
            self.error("Fraudguard.io API key seems to have been rejected or you have exceeded usage limits for the month.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info(f"No Fraudguard.io info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Fraudguard.io: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['fraudguard_api_key_account'] == "" or self.opts['fraudguard_api_key_password'] == "":
            self.error("You enabled GO_fraudguard but did not set an API username/password!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
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

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS', 'NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            evtType = 'MALICIOUS_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS', 'NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
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
            self.results[eventData] = True

        for addr in qrylist:
            if self.checkForStop():
                return

            data = self.query(addr)

            if not data:
                continue

            self.debug(f"Found results for {addr} in Fraudguard.io")

            # Format: 2016-12-24T07:25:35+00:00'
            created_dt = datetime.strptime(data.get('discover_date'), '%Y-%m-%d %H:%M:%S')
            created_ts = int(time.mktime(created_dt.timetuple()))
            age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
            if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                self.debug(f"Record found but too old ({created_dt}), skipping.")
                continue

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

            geoinfo = [
                _f for _f in [
                    data.get('state'),
                    data.get('city'),
                    data.get('postal_code'),
                    data.get('country')
                ] if _f and _f != "unknown"
            ]
            if geoinfo:
                location = ', '.join(filter(None, geoinfo))
                e = GhostOsintEvent("GEOINFO", location, self.__name__, pevent)
                self.notifyListeners(e)

            threat = data.get('threat')
            if threat and threat != "unknown":
                risk_level = data.get('risk_level')
                e = GhostOsintEvent(evtType, f"{threat} (risk level: {risk_level}) [{addr}]", self.__name__, pevent)
                self.notifyListeners(e)

# End of GO_fraudguard class
