# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_etherscan
# Purpose:      GhostOSINT plug-in to look up a ethereum wallet's balance by
#               querying etherscan.io.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     26/01/2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_etherscan(GhostOsintPlugin):

    meta = {
        'name': "Etherscan",
        'summary': "通过 etherscan.io 查询已识别的以太坊钱包地址的余额.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://etherscan.io",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://etherscan.io/apis"
            ],
            'apiKeyInstructions': [
                "访问 https://etherscan.io",
                "注册一个免费账户",
                "浏览 https://etherscan.io/myapikey",
                "点击 API 密钥旁边的 'Add'",
                "你的 API 密钥将列在 API 密钥令牌下",
            ],
            'favIcon': "https://etherscan.io/images/favicon3.ico",
            'logo': "https://etherscan.io/images/brandassets/etherscan-logo-circle.png",
            'description': "Etherscan允许您探索和搜索以太坊区块链中的交易 "
            ", 查找在以太坊（ETH）上发生的交易、地址、代币、价格和其他活动.",
        }
    }

    # Default options
    opts = {
        'api_key': '',
        'pause': 1
    }

    # Option descriptions
    optdescs = {
        'api_key': "etherscan.io API 密钥",
        'pause': "每次API调用之间等待的秒数."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "ETHEREUM_ADDRESS"
        ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [
            "ETHEREUM_BALANCE",
            "RAW_RIR_DATA"
        ]

    def query(self, qry):
        queryString = f"https://api.etherscan.io/api?module=account&action=balance&address={qry}&tag=latest&apikey={self.opts['api_key']}"
        # Wallet balance
        res = self.GhostOsint.fetchUrl(queryString,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['pause'])

        if res['content'] is None:
            self.info(f"No Etherscan data found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled GO_etherscan but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)
        if data is None:
            self.info(f"No Etherscan data found for {eventData}")
            return

        # Value returned by etherscan was too large in comparison to actual wallet balance
        balance = float(data.get('result')) / 1000000000000000000

        evt = GhostOsintEvent("ETHEREUM_BALANCE", f"{str(balance)} ETH", self.__name__, event)
        self.notifyListeners(evt)

        evt = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

# End of GO_etherscan class
