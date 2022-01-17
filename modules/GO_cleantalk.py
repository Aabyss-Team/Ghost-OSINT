# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_cleantalk
# Purpose:     Checks if a netblock or IP address is on CleanTalk.org's spam IP list.
#
# Author:      steve@binarypool.com
#
# Created:     05/08/2018
# Copyright:   (c) Steve Micallef, 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_cleantalk(GhostOsintPlugin):

    meta = {
        'name': "CleanTalk 垃圾邮件列表",
        'summary': "检查网段或 IP地址 是否在 CleanTalk.org 的垃圾邮件列表中.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://cleantalk.org",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://cleantalk.org/help",
                "https://cleantalk.org/help/introduction",
                "https://cleantalk.org/help/api-spam-check",
                "https://cleantalk.org/wordpress-security-malware-firewall",
                "https://cleantalk.org/price-anti-spam",
                "https://cleantalk.org/ssl-certificates/cheap-positivessl-certificate",
                "https://cleantalk.org/email-checker",
                "https://cleantalk.org/blacklists"
            ],
            'favIcon': "https://cleantalk.org/favicons/favicon-16x16.png",
            'logo': "https://cleantalk.org/favicons/favicon-16x16.png",
            'description': "CleanTalk 是一种基于云端的垃圾邮件过滤服务，允许您保护您的网站免受垃圾邮件的影响. "
            "CleanTalk 提供垃圾邮件保护，访问者必须证明自己是真人，不使用验证码或其他方法，访问者就看不见这些垃圾邮件.\n"
            "CleanTalk 为CMS提供云反垃圾邮件解决方案，我们为最流行的CMS开发了插件：WordPress反垃圾邮件插件、Joomla反垃圾邮件插件、Drupal等. "
            "使用我们的云垃圾邮件检查器，您可以确保您的网站不会收到垃圾邮件机器人、垃圾邮件评论.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    optdescs = {
        'checkaffiliates': "对附属IP地址应用检查?",
        'cacheperiod': "提取之前数据缓存.",
        'checknetblocks': "导出在网段中发现的恶意IP地址?",
        'checksubnets': "检查目标的同一子网内的恶意IP地址?"
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
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            'NETBLOCK_OWNER',
            'NETBLOCK_MEMBER'
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
        ]

    def query(self, qry, targetType):
        cid = "_cleantalk"
        url = "https://iplists.firehol.org/files/cleantalk_7d.ipset"

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

            if ip.startswith('#'):
                continue

            if targetType == "netblock":
                try:
                    if IPAddress(ip) in IPNetwork(qry):
                        self.debug(f"{ip} found within netblock/subnet {qry} in CleanTalk Spam List.")
                        return url
                except Exception as e:
                    self.debug(f"Error encountered parsing: {e}")
                    continue

            if targetType == "ip":
                if qry.lower() == ip:
                    self.debug(f"{qry} found in CleanTalk Spam List.")
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

        self.debug(f"Checking maliciousness of {eventData} with CleanTalk Spam List")

        url = self.query(eventData, targetType)

        if not url:
            return

        self.debug(f"{eventData} found in Cleantalk Spam List")

        text = f"CleanTalk Spam List [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = GhostOsintEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = GhostOsintEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of GO_cleantalk class
