# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_abusech
# Purpose:     Check if a host/domain, IP address or netblock is malicious according
#              to Abuse.ch.
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     14/07/2019
# Copyright:   (c) Steve Micallef 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_abusech(GhostOsintPlugin):

    meta = {
        'name': "abuse.ch",
        'summary': "通过 Abuse.ch 检查主机或域名,IP地址和网段是否是恶意地址.",
        'flags': [],
        'useCases': ["Passive", "Investigate"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.abuse.ch",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://feodotracker.abuse.ch/",
                "https://sslbl.abuse.ch/",
                "https://urlhaus.abuse.ch/",
            ],
            'apiKeyInstructions': [
                "访问 https://bazaar.abuse.ch/api#api_key",
                "使用 Twitter 登录",
                "导航到 'Account Settings'",
                "API密钥将在 'Your API Key'",
                "访问 https://urlhaus.abuse.ch/api/",
                "使用 Twitter 账号登录 https://urlhaus.abuse.ch/login/",
                "导航到 https://urlhaus.abuse.ch/api/#account",
                "API密钥将在 'API-Key'"
            ],
            'favIcon': "https://abuse.ch/favicon.ico",
            'logo': "https://abuse.ch/images/abusech.svg",
            'description': "abuse.ch 由瑞士人运营,为非盈利组织的对抗恶意软件, "
            "运营着帮助互联网提供商和网络运营商保护其基础设施免受恶意软件侵害的项目"
            "网络安全研究人员,供应商和执法机构可以通过 abuse.ch 使互联网成为一个更安全的地方.",
        }
    }

    # Default options
    opts = {
        'abusefeodoip': True,
        'abusesslblip': True,
        'abuseurlhaus': True,
        'checkaffiliates': True,
        'checkcohosts': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    # Option descriptions
    optdescs = {
        'abusefeodoip': "启用 abuse.ch 恶意IP地址检查?",
        'abusesslblip': "启用 abuse.ch SSL反向列表IP地址检查?",
        'abuseurlhaus': "启用 abuse.ch URLhaus 检查?",
        'checkaffiliates': "检查关联公司?",
        'checkcohosts': "应用于检查目标IP地址上托管的站点?",
        'cacheperiod': "之前缓存数据提取.",
        'checknetblocks': "报告在网段中发现的任何恶意IP地址?",
        'checksubnets': "检查目标的子网内是否存在恶意IP地址?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "INTERNET_NAME",
            "IP_ADDRESS",
            "NETBLOCK_MEMBER",
            "AFFILIATE_INTERNET_NAME",
            "AFFILIATE_IPADDR",
            "CO_HOSTED_SITE",
            "NETBLOCK_OWNER"
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "MALICIOUS_IPADDR",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_SUBNET",
            "MALICIOUS_COHOST",
            "MALICIOUS_NETBLOCK"
        ]

    def queryFeodoTrackerBlacklist(self, target, targetType):
        blacklist = self.retrieveFeodoTrackerBlacklist()

        if not blacklist:
            return False

        if targetType == "ip":
            if target in blacklist:
                self.debug(f"IP address {target} found in Abuse.ch Feodo Tracker.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in Abuse.ch Feodo Tracker.")
                    return True

        return False

    def retrieveFeodoTrackerBlacklist(self):
        blacklist = self.GhostOsint.cacheGet('abusech_feodo', 24)

        if blacklist is not None:
            return self.parseFeodoTrackerBlacklist(blacklist)

        res = self.GhostOsint.fetchUrl(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from Abuse.ch Abuse.ch Feodo Tracker.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from Abuse.ch Feodo Tracker")
            self.errorState = True
            return None

        self.GhostOsint.cachePut("abusech_feodo", res['content'])

        return self.parseFeodoTrackerBlacklist(res['content'])

    def parseFeodoTrackerBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from Abuse.ch Feodo Tracker

        Returns:
            list: list of blacklisted IP addresses
        """
        ips = list()

        if not blacklist:
            return ips

        for ip in blacklist.split('\n'):
            ip = ip.strip()
            if not ip:
                continue
            if ip.startswith('#'):
                continue
            if not self.GhostOsint.validIP(ip):
                continue
            ips.append(ip)

        return ips

    def querySslBlacklist(self, target, targetType):
        blacklist = self.retrieveSslBlacklist()

        if not blacklist:
            return False

        if targetType == "ip":
            if target in blacklist:
                self.debug(f"IP address {target} found in Abuse.ch SSL Blacklist.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in Abuse.ch SSL Blacklist.")
                    return True

        return False

    def retrieveSslBlacklist(self):
        blacklist = self.GhostOsint.cacheGet('abusech_ssl', 24)

        if blacklist is not None:
            return self.parseSslBlacklist(blacklist)

        res = self.GhostOsint.fetchUrl(
            "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from Abuse.ch Abuse.ch Feodo Tracker.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from Abuse.ch Feodo Tracker")
            self.errorState = True
            return None

        self.GhostOsint.cachePut("abusech_ssl", res['content'])

        return self.parseSslBlacklist(res['content'])

    def parseSslBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): CSV blacklist from Abuse.ch SSL Blacklist

        Returns:
            list: list of blacklisted IP addresses
        """
        ips = list()

        if not blacklist:
            return ips

        for line in blacklist.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                continue
            csv = line.split(',')
            if len(csv) < 2:
                continue
            ip = csv[1]
            if not self.GhostOsint.validIP(ip):
                continue
            ips.append(ip)

        return ips

    def queryUrlHausBlacklist(self, target, targetType):
        blacklist = self.retrieveUrlHausBlacklist()

        if not blacklist:
            return False

        if targetType == "ip":
            if target in blacklist:
                self.debug(f"IP address {target} found in Abuse.ch URL Haus Blacklist.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in blacklist:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in Abuse.ch URL Haus Blacklist.")
                    return True
        elif targetType == "domain":
            if target.lower() in blacklist:
                self.debug(f"Host name {target} found in Abuse.ch URL Haus Blacklist.")
                return True

        return False

    def retrieveUrlHausBlacklist(self):
        blacklist = self.GhostOsint.cacheGet('abusech_urlhaus', 24)

        if blacklist is not None:
            return self.parseUrlHausBlacklist(blacklist)

        res = self.GhostOsint.fetchUrl(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from Abuse.ch URL Haus.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from Abuse.ch URL Haus")
            self.errorState = True
            return None

        self.GhostOsint.cachePut("abusech_urlhaus", res['content'])

        return self.parseUrlHausBlacklist(res['content'])

    def parseUrlHausBlacklist(self, blacklist):
        """Parse plaintext blacklist

        Args:
            blacklist (str): plaintext blacklist from Abuse.ch URL Haus

        Returns:
            list: list of blacklisted hosts
        """
        hosts = list()

        if not blacklist:
            return hosts

        for line in blacklist.split('\n'):
            if not line:
                continue
            if line.startswith('#'):
                continue

            # Note: URL parsing and validation with GhostOsint.validHost() is too slow to use here
            url = line.strip().lower()
            if len(url.split("/")) < 3:
                continue
            host = url.split("/")[2].split(':')[0]
            if not host:
                continue
            if "." not in host:
                continue
            hosts.append(host)

        return hosts

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
            evtType = 'MALICIOUS_IPADDR'
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_NETBLOCK'
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_SUBNET'
        elif eventName == "INTERNET_NAME":
            targetType = 'domain'
            evtType = "MALICIOUS_INTERNET_NAME"
        elif eventName == 'AFFILIATE_INTERNET_NAME':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'domain'
            evtType = 'MALICIOUS_AFFILIATE_INTERNET_NAME'
        elif eventName == 'CO_HOSTED_SITE':
            if not self.opts.get('checkcohosts', False):
                return
            targetType = 'domain'
            evtType = 'MALICIOUS_COHOST'
        else:
            return

        if targetType in ['ip', 'netblock']:
            self.debug(f"Checking maliciousness of {eventData} ({eventName}) with Abuse.ch Feodo Tracker")
            if self.queryFeodoTrackerBlacklist(eventData, targetType):
                url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
                text = f"Abuse.ch Feodo Tracker [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = GhostOsintEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

            self.debug(f"Checking maliciousness of {eventData} ({eventName}) with Abuse.ch SSL Blacklist")
            if self.querySslBlacklist(eventData, targetType):
                url = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
                text = f"Abuse.ch SSL Blacklist [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = GhostOsintEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

        if targetType in ['ip', 'domain']:
            self.debug(f"Checking maliciousness of {eventData} ({eventName}) with Abuse.ch URL Haus")
            if self.queryUrlHausBlacklist(eventData, targetType):
                url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
                text = f"Abuse.ch URL Haus Blacklist [{eventData}]\n<SFURL>{url}</SFURL>"
                evt = GhostOsintEvent(evtType, text, self.__name__, event)
                self.notifyListeners(evt)

# End of GO_abusech class
