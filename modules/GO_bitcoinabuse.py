# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_bitcoinabuse
# Purpose:      Check bitcoin address agains bitcoinabuse.com database
#
# Author:      Leo Trubach <leotrubach@gmail.com>
#
# Created:     2020-09-01
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from urllib.parse import urlencode

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_bitcoinabuse(GhostOsintPlugin):
    meta = {
        "name": "BitcoinAbuse",
        "summary": "根据 bitcoinabuse.com 检查可疑和恶意的比特币地址.",
        'flags': ["apikey"],
        "useCases": ["Passive", "Investigate"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://www.bitcoinabuse.com/",
            "model": "FREE_AUTH_UNLIMITED",
            "references": ["https://www.bitcoinabuse.com/api-docs"],
            "apiKeyInstructions": [
                "访问 https://www.bitcoinabuse.com/register",
                "注册一个免费账户",
                "单击账户图标后单击 'Your Settings'",
                "点击 'API'",
                "输入 Token 后点击 'Create'",
            ],
            "favIcon": "https://www.bitcoinabuse.com/favicon-32x32.png",
            "logo": "https://www.bitcoinabuse.com/img/logo-sm.png",
            "description": "BitcoinAbuse.com 是一个存储黑客、骗子和罪犯使用的比特币地址的公开数据库"
            "如果使用得当, 比特币是匿名的. 幸运的是,  "
            "没用东西是完美的. 甚至黑客也会犯错. 只要一次失误，就可以将被盗比特币与黑客的真实身份联系起来 "
            "我们希望，通过建立罪犯使用的比特币地址的公共数据库，罪犯将更难将数字货币转换回法定货币.",
        },
    }
    opts = {
        "api_key": "",
    }
    optdescs = {
        "api_key": "BitcoinAbuse API 密钥.",
    }
    results = None
    errorState = False

    def setup(self, sfc, userOpts=None):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        if userOpts:
            self.opts.update(userOpts)

    def watchedEvents(self):
        return ["BITCOIN_ADDRESS"]

    def producedEvents(self):
        return ["MALICIOUS_BITCOIN_ADDRESS"]

    def query(self, address):
        params = {"address": address, "api_token": self.opts["api_key"]}
        qry = urlencode(params)
        res = self.GhostOsint.fetchUrl(
            f"https://www.bitcoinabuse.com/api/reports/check?{qry}",
            timeout=self.opts["_fetchtimeout"],
            useragent="GhostOSINT",
        )
        if res["code"] != "200":
            self.info(f"Failed to get results for {address}, code {res['code']}")
            return None

        if res["content"] is None:
            self.info(f"Failed to get results for {address}, empty content")
            return None

        try:
            return json.loads(res["content"])
        except Exception as e:
            self.error(f"Error processing JSON response from BitcoinAbuse: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error("You enabled GO_bitcoinabuse but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "BITCOIN_ADDRESS":
            rec = self.query(eventData)
            if isinstance(rec, dict):
                count = rec.get("count")
                if isinstance(count, int):
                    if count > 0:
                        evt = GhostOsintEvent(
                            "MALICIOUS_BITCOIN_ADDRESS", f"BitcoinAbuse [{rec['address']}][https://www.bitcoinabuse.com/reports/{rec['address']}]", self.__name__, event
                        )
                        self.notifyListeners(evt)

                        rirevt = GhostOsintEvent(
                            "RAW_RIR_DATA", json.dumps(rec), self.__name__, event
                        )
                        self.notifyListeners(rirevt)
