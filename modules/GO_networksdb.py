# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_networksdb
# Purpose:     GhostOSINT plug-in to search NetworksDB.io API for IP address and
#              domain information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-09-16
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_networksdb(GhostOsintPlugin):

    meta = {
        'name': "NetworksDB",
        'summary': "通过 NetworksDB.io API 搜索IP地址和域名信息.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "https://networksdb.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://networksdb.io/api/docs"
            ],
            'apiKeyInstructions': [
                "访问 https://networksdb.io/api/order/free",
                "注册一个免费账户",
                "点击 'Generate a Free API Key'",
                "API 密钥将在 'API Key: Free plan'"
            ],
            'favIcon': "https://networksdb.io/img/favicon/favicon-96x96.png",
            'logo': "https://networksdb.io/img/logo.png",
            'description': "我们的数据库包含有关公共 IPv4 和 IPv6 地址的信息, "
            "全球公司和组织拥有的网络和域名，以及城市级IP地理位置数据和自治系统信息.",
        }
    }
    # Default options
    opts = {
        'api_key': '',
        'delay': 1,
        'verify': True,
        'cohostsamedomain': False,
        'maxcohost': 100
    }

    # Option descriptions
    optdescs = {
        'api_key': 'NetworksDB API 密钥.',
        'delay': '请求之间的延迟（秒）.',
        'verify': "通过检查共享主机是否仍解析为共享IP地址来验证它们是否有效.",
        'cohostsamedomain': "将同一目标域上的托管站点视为共同托管?",
        'maxcohost': "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的."
    }

    cohostcount = 0
    results = None
    errorState = False

    # Initialize module and module options
    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS", "INTERNET_NAME", "DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS", "IPV6_ADDRESS", "NETBLOCK_MEMBER",
                "CO_HOSTED_SITE", "GEOINFO", "RAW_RIR_DATA"]

    # Query IP Address Info
    # https://networksdb.io/api/docs#ipinfo
    def queryIpInfo(self, qry):
        params = {
            'ip': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
        }
        headers = {
            'Accept': 'application/json',
            'X-Api-Key': self.opts['api_key'],
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        res = self.GhostOsint.fetchUrl('https://networksdb.io/api/ip-info',
                               headers=headers,
                               postData=urllib.parse.urlencode(params),
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query IP Geolocation
    # https://networksdb.io/api/docs#geoip
    def queryIpGeo(self, qry):
        params = {
            'ip': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
        }
        headers = {
            'Accept': 'application/json',
            'X-Api-Key': self.opts['api_key'],
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        res = self.GhostOsint.fetchUrl('https://networksdb.io/api/ip-geo',
                               headers=headers,
                               postData=urllib.parse.urlencode(params),
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query Domains on IP (Reverse DNS)
    # https://networksdb.io/api/docs#revdns
    def queryReverseDns(self, qry):
        params = {
            'ip': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
        }
        headers = {
            'Accept': 'application/json',
            'X-Api-Key': self.opts['api_key'],
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        res = self.GhostOsint.fetchUrl('https://networksdb.io/api/reverse-dns',
                               headers=headers,
                               postData=urllib.parse.urlencode(params),
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query IPs for Domain (Forward DNS)
    # https://networksdb.io/api/docs#fwddns
    def queryForwardDns(self, qry):
        params = {
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
        }
        headers = {
            'Accept': 'application/json',
            'X-Api-Key': self.opts['api_key'],
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        res = self.GhostOsint.fetchUrl('https://networksdb.io/api/dns',
                               headers=headers,
                               postData=urllib.parse.urlencode(params),
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query Autonomous System Info
    # https://networksdb.io/api/docs#asinfo
    # Note: currently unused
    def queryAsnInfo(self, qry):
        params = {
            'asn': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
        }
        headers = {
            'Accept': 'application/json',
            'X-Api-Key': self.opts['api_key'],
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        res = self.GhostOsint.fetchUrl('https://networksdb.io/api/asn',
                               headers=headers,
                               postData=urllib.parse.urlencode(params),
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query Autonomous System Networks
    # https://networksdb.io/api/docs#asnets
    # Note: currently unused
    def queryAsnNetworks(self, qry):
        params = {
            'asn': qry,
        }
        headers = {
            'Accept': 'application/json',
            'X-Api-Key': self.opts['api_key'],
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        res = self.GhostOsint.fetchUrl('https://networksdb.io/api/asn-networks',
                               headers=headers,
                               postData=urllib.parse.urlencode(params),
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Parse API response
    # https://networksdb.io/api/plans
    def parseApiResponse(self, res):
        # Future proofing - NetworksDB does not implement rate limiting
        if res['code'] == '429':
            self.error("You are being rate-limited by NetworksDB")
            self.errorState = True
            return None

        if res['code'] == '403':
            self.error("Authentication failed")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from NetworksDB: {e}")
            return None

        if data.get('warning'):
            self.debug("Received warning from NetworksDB: " + data.get('warning'))

        if data.get('error'):
            self.error("Received error from NetworksDB: " + data.get('error'))

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            return

        if self.opts['api_key'] == '':
            self.error("You enabled GO_networksdb but did not set an API key!")
            self.errorState = True
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName in ["IP_ADDRESS", "IPV6_ADDRESS"]:
            data = self.queryIpInfo(eventData)

            if data is None:
                self.debug("No IP address information found for " + eventData)
            else:
                evt = GhostOsintEvent('RAW_RIR_DATA', str(data), self.__name__, event)
                self.notifyListeners(evt)

                network = data.get('network')
                if network:
                    cidr = network.get('cidr')
                    if cidr and cidr != 'N/A' and self.GhostOsint.validIpNetwork(cidr):
                        if ":" in cidr:
                            evt = GhostOsintEvent('NETBLOCKV6_MEMBER', cidr, self.__name__, event)
                        else:
                            evt = GhostOsintEvent('NETBLOCK_MEMBER', cidr, self.__name__, event)
                        self.notifyListeners(evt)

            data = self.queryIpGeo(eventData)

            if data is None:
                self.debug("No IP geolocation information found for " + eventData)
            else:
                evt = GhostOsintEvent('RAW_RIR_DATA', str(data), self.__name__, event)
                self.notifyListeners(evt)

                if data.get('country'):
                    location = ', '.join(filter(None, [data.get('city'), data.get('state'), data.get('country')]))
                    evt = GhostOsintEvent('GEOINFO', location, self.__name__, event)
                    self.notifyListeners(evt)

            data = self.queryReverseDns(eventData)

            cohosts = list()

            if data is None:
                self.debug("No reverse DNS results for " + eventData)
            else:
                evt = GhostOsintEvent('RAW_RIR_DATA', str(data), self.__name__, event)
                self.notifyListeners(evt)

                results = data.get('results')
                if results:
                    for domain in results:
                        cohosts.append(domain)

            for co in set(cohosts):
                if self.checkForStop():
                    return

                if co in self.results:
                    continue

                if self.opts['verify'] and not self.GhostOsint.validateIP(co, eventData):
                    self.debug("Host " + co + " no longer resolves to " + eventData)
                    continue

                if not self.opts['cohostsamedomain']:
                    if self.getTarget().matches(co, includeParents=True):
                        evt = GhostOsintEvent('INTERNET_NAME', co, self.__name__, event)
                        self.notifyListeners(evt)
                        if self.GhostOsint.isDomain(co, self.opts['_internettlds']):
                            evt = GhostOsintEvent('DOMAIN_NAME', co, self.__name__, event)
                            self.notifyListeners(evt)
                        continue

                if self.cohostcount < self.opts['maxcohost']:
                    evt = GhostOsintEvent('CO_HOSTED_SITE', co, self.__name__, event)
                    self.notifyListeners(evt)
                    self.cohostcount += 1

        if eventName in ["INTERNET_NAME", "DOMAIN_NAME"]:
            data = self.queryForwardDns(eventData)

            if data is None:
                self.debug("No forward DNS results for " + eventData)
                return

            res = data.get('results')

            if not res:
                self.debug("No forward DNS results for " + eventData)
                return

            evt = GhostOsintEvent('RAW_RIR_DATA', str(res), self.__name__, event)
            self.notifyListeners(evt)

            for ip in res:
                if self.GhostOsint.validIP(ip):
                    evt = GhostOsintEvent('IP_ADDRESS', ip, self.__name__, event)
                    self.notifyListeners(evt)
                elif self.GhostOsint.validIP6(ip):
                    evt = GhostOsintEvent('IPV6_ADDRESS', ip, self.__name__, event)
                    self.notifyListeners(evt)

# End of GO_networksdb class
