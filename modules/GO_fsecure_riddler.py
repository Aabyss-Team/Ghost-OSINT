# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_fsecure_riddler
# Purpose:     Query F-Secure Riddler.io API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-09-16
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_fsecure_riddler(GhostOsintPlugin):

    meta = {
        'name': "F-Secure Riddler.io",
        'summary': "从 F-Secure Riddler.io API 密钥获取网络信息.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://riddler.io/",
            'model': "PRIVATE_ONLY",
            'references': [
                "https://riddler.io/help/api",
                "https://riddler.io/help/search",
                "https://riddler.io/static/riddler_white_paper.pdf",
                "https://www.f-secure.com/en/business/products/vulnerability-management/radar"
            ],
            'apiKeyInstructions': [
                "对新账户禁止注册了"
            ],
            'favIcon': "https://riddler.io/static/images/favicon.png",
            'logo': "https://riddler.io/static/images/logo.png",
            'description': "Riddler.io 允许您在包含超过396831739个主机名的高质量数据集中搜索. "
            "与其他人不同，我们不依赖简单的端口扫描技术——我们在网络上爬行，确保您在其他任何地方都找不到深入的高质量数据集.\n"
            "在渗透测试期间，使用 Riddler 枚举可能的攻击向量，或者在为时已晚之前，使用完全相同的数据监控潜在的威胁.",
        }
    }

    opts = {
        'verify': True,
        'username': '',
        'password': ''
    }

    optdescs = {
        'verify': '验证主机名解析',
        'username': 'F-Secure Riddler.io 用户名',
        'password': 'F-Secure Riddler.io 密码'
    }

    results = None
    token = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['DOMAIN_NAME', 'INTERNET_NAME',
                'INTERNET_NAME_UNRESOLVED', 'IP_ADDRESS']

    def producedEvents(self):
        return ['INTERNET_NAME', 'AFFILIATE_INTERNET_NAME',
                'INTERNET_NAME_UNRESOLVED', 'AFFILIATE_INTERNET_NAME_UNRESOLVED',
                'DOMAIN_NAME', 'AFFILIATE_DOMAIN_NAME',
                'IP_ADDRESS',
                'PHYSICAL_COORDINATES', 'RAW_RIR_DATA']

    # https://riddler.io/help/api
    def login(self):
        params = {
            'email': self.opts['username'].encode('raw_unicode_escape').decode("ascii"),
            'password': self.opts['password'].encode('raw_unicode_escape').decode("ascii")
        }
        headers = {
            'Content-Type': 'application/json',
        }

        res = self.GhostOsint.fetchUrl('https://riddler.io/auth/login',
                               postData=json.dumps(params),
                               headers=headers,
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        if res['content'] is None:
            return

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from F-Secure Riddler: {e}")
            return

        try:
            token = data.get('response').get('user').get('authentication_token')
        except Exception:
            self.error('Login failed')
            self.errorState = True
            return

        if not token:
            self.error('Login failed')
            self.errorState = True
            return

        self.token = token

    # https://riddler.io/help/search
    def query(self, qry):
        params = {
            'query': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }
        headers = {
            'Authentication-Token': self.token,
            'Content-Type': 'application/json',
        }

        res = self.GhostOsint.fetchUrl('https://riddler.io/api/search',
                               postData=json.dumps(params),
                               headers=headers,
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        time.sleep(1)

        if res['code'] in ["400", "401", "402", "403"]:
            self.error('Unexpected HTTP response code: ' + res['code'])
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from F-Secure Riddler: {e}")
            return None

        if not data:
            self.debug("No results found for " + qry)
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if srcModuleName == 'GO_fsecure_riddler':
            self.debug("Ignoring " + eventData + ", from self.")
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.opts['username'] == '' or self.opts['password'] == '':
            self.error('You enabled GO_fsecure_riddler but did not set an API username/password!')
            self.errorState = True
            return

        if not self.token:
            self.login()

        self.results[eventData] = True

        data = None

        if eventName in ['INTERNET_NAME', 'DOMAIN_NAME']:
            data = self.query("pld:" + eventData)
        elif eventName == 'IP_ADDRESS':
            data = self.query("ip:" + eventData)

        if not data:
            self.info("No results found for " + eventData)
            return

        e = GhostOsintEvent('RAW_RIR_DATA', str(data), self.__name__, event)
        self.notifyListeners(e)

        hosts = list()
        addrs = list()
        coords = list()

        for result in data:
            host = result.get('host')

            if not host:
                continue

            if not self.getTarget().matches(host, includeChildren=True, includeParents=True):
                continue

            hosts.append(host)

            addr = result.get('addr')

            if addr:
                addrs.append(addr)

            coord = result.get('cordinates')

            if coord and len(coord) == 2:
                coords.append(str(coord[0]) + ', ' + str(coord[1]))

        if self.opts['verify'] and len(hosts) > 0:
            self.info("Resolving " + str(len(set(hosts))) + " domains ...")

        for host in set(hosts):
            if self.getTarget().matches(host, includeChildren=True, includeParents=True):
                evt_type = 'INTERNET_NAME'
            else:
                evt_type = 'AFFILIATE_INTERNET_NAME'

            if self.opts['verify'] and not self.GhostOsint.resolveHost(host) and not self.GhostOsint.resolveHost6(host):
                self.debug(f"Host {host} could not be resolved")
                evt_type += '_UNRESOLVED'

            evt = GhostOsintEvent(evt_type, host, self.__name__, event)
            self.notifyListeners(evt)

            if self.GhostOsint.isDomain(host, self.opts['_internettlds']):
                if evt_type.startswith('AFFILIATE'):
                    evt = GhostOsintEvent('AFFILIATE_DOMAIN_NAME', host, self.__name__, event)
                    self.notifyListeners(evt)
                else:
                    evt = GhostOsintEvent('DOMAIN_NAME', host, self.__name__, event)
                    self.notifyListeners(evt)

        for addr in set(addrs):
            if self.GhostOsint.validIP(addr):
                evt = GhostOsintEvent('IP_ADDRESS', addr, self.__name__, event)
                self.notifyListeners(evt)

        for coord in set(coords):
            evt = GhostOsintEvent('PHYSICAL_COORDINATES', coord, self.__name__, event)
            self.notifyListeners(evt)

# End of GO_fsecure_riddler class
