# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_multiproxy
# Purpose:     Check if an IP arress is an open proxy according to multiproxy.org
#              open proxy list.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_multiproxy(GhostOsintPlugin):

    meta = {
        'name': "multiproxy.org 开放代理",
        'summary': " 根据 multiproxy.org 开放代理列表检查IP地址是否为开放代理.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Secondary Networks"],
        'dataSource': {
            'website': "https://multiproxy.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://multiproxy.org/faq.htm",
                "https://multiproxy.org/env_check.htm",
                "https://multiproxy.org/anon_proxy.htm",
                "https://multiproxy.org/help.htm"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://multiproxy.org/",
            'logo': "https://multiproxy.org/images/mproxy_title.png",
            'description': "MultiProxy 是一个多功能的个人代理服务器，在互联网上保护你的隐私，并加快你的下载速度，"
            "特别是当您试图从海外或其他速度较慢的服务器获取多个文件时. "
            "它还可以通过动态连接到不透明的匿名公共代理服务器来完全隐藏您的IP地址. "
            "你还可以测试代理服务器列表，并根据连接速度和匿名级别对其进行排序.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18
    }

    optdescs = {
        'checkaffiliates': "检查关联企业?",
        'cacheperiod': "之前缓存数据提取."
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
            'NETBLOCK_MEMBER',
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

    def queryProxyList(self, target, targetType):
        proxy_list = self.retrieveProxyList()

        if not proxy_list:
            self.errorState = True
            return False

        if targetType == "ip":
            if target in proxy_list:
                self.debug(f"IP address {target} found in multiproxy.org open proxy list.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in proxy_list:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in multiproxy.org open proxy list.")
                    return True

        return False

    def retrieveProxyList(self):
        proxy_list = self.GhostOsint.cacheGet('multiproxyopenproxies', 24)

        if proxy_list is not None:
            return self.parseProxyList(proxy_list)

        res = self.GhostOsint.fetchUrl(
            "http://multiproxy.org/txt_all/proxy.txt",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from multiproxy.org.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from multiproxy.org")
            self.errorState = True
            return None

        self.GhostOsint.cachePut("multiproxyopenproxies", res['content'])

        return self.parseProxyList(res['content'])

    def parseProxyList(self, proxy_list):
        """Parse plaintext open proxy list

        Args:
            proxy_list (str): plaintext open proxy list from multiproxy.org

        Returns:
            list: list of open proxy IP addresses
        """
        ips = list()

        if not proxy_list:
            return ips

        for ip in proxy_list.split('\n'):
            ip = ip.strip().split(":")[0]
            if ip.startswith('#'):
                continue
            if not self.GhostOsint.validIP(ip):
                continue
            ips.append(ip)

        return ips

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

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

        self.debug(f"Checking maliciousness of {eventData} ({eventName}) with multiproxy.org open proxy list")

        if not self.queryProxyList(eventData, targetType):
            return

        url = "http://multiproxy.org/txt_all/proxy.txt"
        text = f"multiproxy.org Open Proxies [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = GhostOsintEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = GhostOsintEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of GO_multiproxy class
