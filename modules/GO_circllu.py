# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_circllu
# Purpose:      Query circl.lu using their API
#
# Author:      Steve Micallef
#
# Created:     16/02/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import base64
import json
import re
import time

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_circllu(GhostOsintPlugin):

    meta = {
        'name': "CIRCL.LU",
        'summary': "通过 CIRCL.LU 数据库获取 DNS 和 SSL 证书信息.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.circl.lu/",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://www.circl.lu/services/passive-dns/",
                "https://www.circl.lu/services/passive-ssl/",
                "https://www.circl.lu/services/",
                "https://www.circl.lu/pub/",
                "https://www.circl.lu/projects"
            ],
            'apiKeyInstructions': [
                "访问 https://www.circl.lu/contact/",
                "通过电子邮件或电话，请求访问被动 DNS 查询和被动 SSL证书 查询的 API 服务",
                "一旦获得批准，将提供 API 访问权限"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://www.circl.lu/",
            'logo': "https://www.circl.lu/assets/images/circl-logo.png",
            'description': "Computer Incident Response Center Luxembourg (CIRCL) 是一个由政府推动的倡议，旨在收集、审查、报告和响应计算机安全威胁和事件.\n"
            "CIRCL为卢森堡境内的任何用户、公司和组织提供可靠和可信的联络点，以处理攻击和事件. "
            "它的专家团队就像一支消防队，能够在怀疑、发现威胁或发生事故时迅速有效地作出反应.",
        }
    }

    # Default options
    opts = {
        "api_key_login": "",
        "api_key_password": "",
        "age_limit_days": 0,
        "verify": True,
        "cohostsamedomain": False,
        "maxcohost": 100
    }

    # Option descriptions
    optdescs = {
        "api_key_login": "CIRCL.LU 用户名.",
        "api_key_password": "CIRCL.LU 密码.",
        "age_limit_days": "忽略之前的 被动DNS 记录. 0 = 无线.",
        "verify": "通过检查共享主机是否仍解析为共享IP地址来验证它们是否有效.",
        "cohostsamedomain": "将同一目标上的托管站点视为共同托管?",
        'maxcohost': "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME", "NETBLOCK_OWNER", "IP_ADDRESS", "DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["IP_ADDRESS", "SSL_CERTIFICATE_ISSUED", "CO_HOSTED_SITE"]

    def query(self, qry, qtype):
        if self.errorState:
            return None

        if qtype == "PDNS":
            url = "https://www.circl.lu/pdns/query/" + qry
        else:
            url = "https://www.circl.lu/v2pssl/query/" + qry

        secret = self.opts['api_key_login'] + ':' + self.opts['api_key_password']
        b64_val = base64.b64encode(secret.encode('utf-8'))
        headers = {
            'Authorization': f"Basic {b64_val.decode('utf-8')}"
        }

        # Be more forgiving with the timeout as some queries for subnets can be slow
        res = self.GhostOsint.fetchUrl(url, timeout=30,
                               useragent="GhostOSINT", headers=headers)

        if res['code'] not in ["200", "201"]:
            self.error("CIRCL.LU access seems to have been rejected or you have exceeded usage limits.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info("No CIRCL.LU info found for " + qry)
            return None

        return res['content']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        ret = None

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Ignore messages from myself
        if srcModuleName == "GO_circllu":
            self.debug("Ignoring " + eventName + ", from self.")
            return

        if self.opts['api_key_login'] == "" or self.opts['api_key_password'] == "":
            self.error("You enabled GO_circllu but did not set an credentials!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName in ['IP_ADDRESS', 'NETBLOCK_OWNER']:
            # CIRCL.LU limit the maximum subnet size to 23
            # http://circl.lu/services/passive-ssl/
            if "/" in eventData:
                addr, mask = eventData.split("/")
                if int(mask) < 23:
                    self.debug("Network size bigger than permitted by CIRCL.LU.")
                else:
                    ret = self.query(eventData, "PSSL")
                    if not ret:
                        self.info("No CIRCL.LU passive SSL data found for " + eventData)
            else:
                ret = self.query(eventData, "PSSL")
                if not ret:
                    self.info("No CIRCL.LU passive SSL data found for " + eventData)

            if ret:
                try:
                    # Generate an event for the IP first, and then link the cert
                    # to that event.
                    j = json.loads(ret)
                    for ip in j:
                        ipe = event
                        if ip != eventData:
                            ipe = GhostOsintEvent("IP_ADDRESS", ip, self.__name__, event)
                            self.notifyListeners(ipe)
                        for crt in j[ip]['subjects']:
                            r = re.findall(r".*[\"\'](.+CN=([a-zA-Z0-9\-\*\.])+)[\"\'].*",
                                           str(j[ip]['subjects'][crt]), re.IGNORECASE)
                            if r:
                                e = GhostOsintEvent("SSL_CERTIFICATE_ISSUED", r[0][0], self.__name__, ipe)
                                self.notifyListeners(e)
                except Exception as e:
                    self.error("Invalid response returned from CIRCL.LU: " + str(e))

        if eventName in ['IP_ADDRESS', 'INTERNET_NAME', 'DOMAIN_NAME']:
            ret = self.query(eventData, "PDNS")
            if not ret:
                self.info("No CIRCL.LU passive DNS data found for " + eventData)
                return

            # CIRCL.LU doesn't return valid JSON - it's one JSON record per line
            for line in ret.split("\n"):
                if len(line) < 2:
                    continue
                try:
                    rec = json.loads(line)
                except Exception as e:
                    self.error("Invalid response returned from CIRCL.LU: " + str(e))
                    continue

                age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                if self.opts['age_limit_days'] > 0 and rec['time_last'] < age_limit_ts:
                    self.debug("Record found but too old, skipping.")
                    continue

                cohosts = list()
                if eventName == "IP_ADDRESS":
                    # Record could be pointing to our IP, or from our IP
                    if rec['rrtype'] == "A" and rec['rdata'] == eventData:
                        if not self.getTarget().matches(rec['rrname']):
                            # We found a co-host
                            cohosts.append(rec['rrname'])

                if eventName in ["INTERNET_NAME", "DOMAIN_NAME"]:
                    # Record could be an A/CNAME of this entity, or something pointing to it
                    if rec['rdata'] == eventData:
                        if not self.getTarget().matches(rec['rrname']):
                            # We found a co-host
                            cohosts.append(rec['rrname'])

                for co in cohosts:
                    if eventName == "IP_ADDRESS" and (self.opts['verify'] and not self.GhostOsint.validateIP(co, eventData)):
                        self.debug("Host no longer resolves to our IP.")
                        continue

                    if not self.opts['cohostsamedomain']:
                        if self.getTarget().matches(co, includeParents=True):
                            self.debug("Skipping " + co + " because it is on the same domain.")
                            continue

                    if self.cohostcount < self.opts['maxcohost']:
                        e = GhostOsintEvent("CO_HOSTED_SITE", co, self.__name__, event)
                        self.notifyListeners(e)
                        self.cohostcount += 1

# End of GO_circllu class
