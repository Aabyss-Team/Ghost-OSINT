# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_cinsscore
# Purpose:     Checks if an IP address is malicious according to the CINS Army list.
#
# Author:      steve@binarypool.com
#
# Created:     13/05/2018
# Copyright:   (c) Steve Micallef, 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_cinsscore(GhostOsintPlugin):

    meta = {
        'name': "CINS 威胁情报",
        'summary': "根据 Collective Intelligence Network Security (CINS) 检查网段或IP地址是否是恶意的.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://cinsscore.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'favIcon': 'https://cinsscore.com/media/images/fav-icon.png',
            'logo': 'https://cinsscore.com/media/images/logo-small-grey-inset.png',
            'description': "CINS是一个威胁情报数据库，利用我们的哨兵设备网络和其他可信信息安全来源的数据，为世界上任何IP地址提供准确及时的评分.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    optdescs = {
        'checkaffiliates': "对附属 IP地址 应用检查?",
        'cacheperiod': "之前缓存数据提取.",
        'checknetblocks': "导出网段中发现的任何恶意IP?",
        'checksubnets': "检查在目标的同一子网内是否发现任何恶意 IP地址 ?"
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
            "AFFILIATE_IPADDR",
            "NETBLOCK_MEMBER",
            "NETBLOCK_OWNER",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_SUBNET",
            "MALICIOUS_NETBLOCK",
        ]

    def query(self, qry, targetType):
        cid = "_cinsscore"
        url = "https://cinsscore.com/list/ci-badguys.txt"

        data = dict()
        data["content"] = self.GhostOsint.cacheGet("sfmal_" + cid, self.opts.get('cacheperiod', 0))

        if data["content"] is None:
            data = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

            if data["code"] != "200":
                self.error(f"Unable to fetch {url}")
                self.errorState = True
                return None

            if data["content"] is None:
                self.error(f"Unable to fetch {url}")
                self.errorState = True
                return None

            self.GhostOsint.cachePut("sfmal_" + cid, data['content'])

        for line in data["content"].split('\n'):
            ip = line.strip().lower()

            if targetType == "netblock":
                try:
                    if IPAddress(ip) in IPNetwork(qry):
                        self.debug(f"{ip} found within netblock/subnet {qry} in cinsscore.com list.")
                        return url
                except Exception as e:
                    self.debug(f"Error encountered parsing: {e}")
                    continue

            if targetType == "ip":
                if qry.lower() == ip:
                    self.debug(f"{qry} found in cinsscore.com list.")
                    return url

        return None

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

        if eventName == 'IP_ADDRESS':
            targetType = 'ip'
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.debug(f"Checking maliciousness of {eventData} with cinsscore.com")

        url = self.query(eventData, targetType)

        if not url:
            return

        text = f"cinsscore.com [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = GhostOsintEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = GhostOsintEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of GO_cinsscore class
