# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_bitcoinwhoswho
# Purpose:      Bitcoin Who's Who database lookup module
#
# Author:      Leo Trubach <leotrubach@gmail.com>
#
# Created:     2020-09-09
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib.parse

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_bitcoinwhoswho(GhostOsintPlugin):
    meta = {
        'name': "Bitcoin 名人录",
        'summary': "根据比特币名人录数据库检查该比特币地址是否是可疑的或恶意的.",
        'flags': ["apikey"],
        'useCases': ["Passive", "Investigate"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://bitcoinwhoswho.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://bitcoinwhoswho.com/api"
            ],
            'apiKeyInstructions': [
                "访问 https://bitcoinwhoswho.com/signup",
                "注册一个免费账户",
                "验证你的电子邮件并登录账户",
                "访问 https://bitcoinwhoswho.com/api/register 并请求 API 密钥",
                "等待几天，邮件就来了"
            ],
            'favIcon': "https://bitcoinwhoswho.com/public/images/ico/favicon.ico",
            'logo': "https://bitcoinwhoswho.com/public/images/logo2.png",
            'description': (
                "比特币名人录致力于介绍比特币生态系统的杰出成员.我们的目标是帮助你验证比特币地址所有者并避免比特币的 "
                "骗局和欺诈."
            ),
        }
    }

    opts = {
        'api_key': '',
    }

    optdescs = {
        "api_key": "Bitcoin 名人录 API 密钥."
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

    def query(self, qry):
        qs = urllib.parse.urlencode({"address": qry})
        res = self.GhostOsint.fetchUrl(
            f"https://bitcoinwhoswho.com/api/scam/{self.opts['api_key']}?{qs}",
            timeout=self.opts["_fetchtimeout"],
            useragent="GhostOSINT",
        )

        if res["content"] is None:
            self.info(f"No {self.meta['name']} info found for {qry}")
            return None

        try:
            return json.loads(res["content"])
        except Exception as e:
            self.error(f"Error processing JSON response from {self.meta['name']}: {e}")

        return None

    def emit(self, etype, data, pevent, notify=True):
        evt = GhostOsintEvent(etype, data, self.__name__, pevent)
        if notify:
            self.notifyListeners(evt)
        return evt

    def generate_events(self, data, pevent):
        if not isinstance(data, dict):
            return False

        scams = data.get("scams", [])
        if scams:
            self.emit("MALICIOUS_BITCOIN_ADDRESS", f"Bitcoin Who's Who [{pevent.data}][https://bitcoinwhoswho.com/address/{pevent.data}]", pevent)
            return True

        return False

    def handleEvent(self, event):
        if self.errorState:
            return

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        if self.opts["api_key"] == "":
            self.error(f"You enabled {self.__class__.__name__} but did not set an API key!")
            self.errorState = True
            return

        if event.data in self.results:
            self.debug(f"Skipping {event.data}, already checked.")
            return
        self.results[event.data] = True

        if event.eventType == "BITCOIN_ADDRESS":
            data = self.query(event.data)
            r = self.generate_events(data, event)

            if r:
                self.emit("RAW_RIR_DATA", json.dumps(data), event)

# End of GO_bitcoinwhoswho class
