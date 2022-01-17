# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_isc
# Purpose:      Check if an IP address is malicious according to SANS ISC.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_isc(GhostOsintPlugin):

    meta = {
        'name': "Internet Storm Center",
        'summary': "根据 SANS ISC 检查IP地址是否为恶意地址.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://isc.sans.edu",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://isc.sans.edu/api/",
                "https://isc.sans.edu/howto.html",
                "https://isc.sans.edu/honeypot.html",
                "https://isc.sans.edu/glossary.html",
                "https://isc.sans.edu/fightback.html"
            ],
            'favIcon': "https://isc.sans.edu/iscfavicon.ico",
            'logo': "https://isc.sans.edu/images/logos/isc/large.png",
            'description': "ISC 向数千名互联网用户和组织提供免费分析和警告服务，并积极与互联网服务提供商合作，打击最恶意的攻击者.\n"
            "与大多数防火墙、入侵检测系统、家庭宽带设备和几乎所有操作系统一起工作的数以万计的传感器不断收集来自互联网的不必要流量的信息. "
            "这些设备为 DShield 数据库提供数据，在那里，人类志愿者和机器通过数据寻找异常趋势和行为. "
            "由此产生的分析被发布到 ISC 的主页上，在那里可以通过简单的脚本自动检索，也可以被任何互联网用户近实时地查看.",
        }
    }

    opts = {
        'checkaffiliates': True
    }

    optdescs = {
        'checkaffiliates': "检查关联企业?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
        ]

    def query(self, ip):
        if not ip:
            return None

        res = self.GhostOsint.fetchUrl(
            f"https://isc.sans.edu/api/ip/{ip}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from ISC.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from ISC")
            self.errorState = True
            return None

        return res['content']

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            malicious_type = 'MALICIOUS_IPADDR'
            blacklist_type = 'BLACKLISTED_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = 'MALICIOUS_AFFILIATE_IPADDR'
            blacklist_type = 'BLACKLISTED_AFFILIATE_IPADDR'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        data = self.query(eventData)

        if not data:
            return

        attacks = re.findall(r"<attacks>([0-9]+)</attacks>", data)

        if not attacks:
            return

        url = f"https://isc.sans.edu/api/ip/{eventData}"
        text = f"Internet Storm Center [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = GhostOsintEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = GhostOsintEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of GO_isc class
