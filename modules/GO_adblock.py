# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_adblock
# Purpose:      GhostOSINT plug-in to test if external/internally linked pages
#               would be blocked by AdBlock Plus.
# -------------------------------------------------------------------------------

import adblockparser

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_adblock(GhostOsintPlugin):

    meta = {
        'name': "AdBlock 检查",
        'summary': "检查链接页面是否会被 AdBlock Plus 阻止.",
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://adblockplus.org/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://help.eyeo.com/en/adblockplus/",
                "https://adblockplus.org/en/download",
                "https://adblockplus.org/en/filters#options",
                "https://chrome.google.com/webstore/detail/adblock-plus-free-ad-bloc/cfhdojbkjhnklbpkdaibdccddilifddb"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://adblockplus.org/en/",
            'logo': "https://adblockplus.org/img/navbar-logo.svg",
            'description': "Adblock Plus 是一个免费扩展插件，允许你自定义WEB体验."
            "你可以阻止烦人的广告, 禁用跟踪等等."
            "适用于所有主要的桌面浏览器和移动设备.\n"
            "阻止或中断你浏览的广告."
            "告别视频广告, 弹出窗口, 横幅广告等."
            "阻止这些玩意加载, 你的页面加载也会变得更加快速.\n"
            "使用 Adblock Plus 可轻松避免跟踪和恶意软件."
            "阻止侵入性广告可降低 \"恶意\" 感染的风险."
            "阻止跟踪会阻止公司跟踪你的在线活动."
        }
    }

    # Default options
    opts = {
        "blocklist": "https://easylist-downloads.adblockplus.org/easylist.txt",
        'cacheperiod': 24,
    }

    optdescs = {
        "blocklist": "AdBlock Plus 阻止列表.",
        'cacheperiod': "之前缓存数据提取.",
    }

    results = None
    rules = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.rules = None
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL", "LINKED_URL_EXTERNAL", "PROVIDER_JAVASCRIPT"]

    # What events this module produces
    def producedEvents(self):
        return ["URL_ADBLOCKED_INTERNAL", "URL_ADBLOCKED_EXTERNAL"]

    def retrieveBlocklist(self, blocklist_url):
        if not blocklist_url:
            return None

        blocklist = self.GhostOsint.cacheGet(f"adblock_{blocklist_url}", 24)

        if blocklist is not None:
            return self.setBlocklistRules(blocklist)

        res = self.GhostOsint.fetchUrl(blocklist_url, timeout=30)

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} for {blocklist_url}")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error(f"Unable to download AdBlock Plus blocklist: {blocklist_url}")
            self.errorState = True
            return None

        self.GhostOsint.cachePut(f"adblock_{blocklist_url}", res['content'])

        return self.setBlocklistRules(res['content'])

    def setBlocklistRules(self, blocklist):
        """Parse AdBlock Plus blocklist and set blocklist rules

        Args:
            blocklist (str): plaintext AdBlock Plus blocklist
        """
        if not blocklist:
            return

        lines = blocklist.split('\n')
        self.debug(f"Retrieved {len(lines)} AdBlock blocklist rules")
        try:
            self.rules = adblockparser.AdblockRules(lines)
        except adblockparser.AdblockParsingError as e:
            self.errorState = True
            self.error(f"Parsing error handling AdBlock list: {e}")

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug("Already checked this URL for AdBlock matching, skipping.")
            return

        self.results[eventData] = True

        if self.errorState:
            return

        if not self.opts["blocklist"]:
            self.error(
                f"You enabled {self.__class__.__name__} but did not set a blocklist URL!"
            )
            self.errorState = True
            return

        if not self.rules:
            self.retrieveBlocklist(self.opts['blocklist'])

        if not self.rules:
            self.error("No AdBlock Plus rules loaded")
            self.errorState = True
            return

        try:
            if eventName == 'PROVIDER_JAVASCRIPT':
                if self.rules and self.rules.should_block(eventData, {'third-party': True, 'script': True}):
                    evt = GhostOsintEvent("URL_ADBLOCKED_EXTERNAL", eventData, self.__name__, event)
                    self.notifyListeners(evt)

            if eventName == 'LINKED_URL_EXTERNAL':
                if self.rules and self.rules.should_block(eventData, {'third-party': True}):
                    evt = GhostOsintEvent("URL_ADBLOCKED_EXTERNAL", eventData, self.__name__, event)
                    self.notifyListeners(evt)

            if eventName == 'LINKED_URL_INTERNAL':
                if self.rules and self.rules.should_block(eventData):
                    evt = GhostOsintEvent("URL_ADBLOCKED_INTERNAL", eventData, self.__name__, event)
                    self.notifyListeners(evt)

        except ValueError as e:
            self.error(f"Parsing error handling AdBlock list: {e}")
            self.errorState = True

# End of GO_adblock class
