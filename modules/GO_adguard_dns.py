# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_adguard_dns
# Purpose:     GhostOSINT plug-in for looking up whether hosts are blocked by
#              AdGuard DNS servers.
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     14/07/2019
# Copyright:   (c) Steve Micallef 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import dns.resolver

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_adguard_dns(GhostOsintPlugin):

    meta = {
        'name': "AdGuard DNS",
        'summary': "检查主机是否会被 AdGuard DNS 阻止.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://adguard.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://adguard.com/en/adguard-dns/overview.html",
            ],
            'favIcon': "https://adguard.com/img/favicons/favicon.ico",
            'logo': "https://adguard.com/img/favicons/apple-touch-icon.png",
            'description': "AdGuard DNS 是不需要安装任何应用程序阻止互联网广告的万无一失的方法. "
            "它易于使用, 绝对免费, 易于在任何设备上设置,并为您提供最少的必要功能 "
            "阻止广告、加载器、恶意网站和成人内容."
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME",
            "CO_HOSTED_SITE"
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_INTERNET_NAME",
            "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            "BLACKLISTED_COHOST",
        ]

    def queryDefaultDNS(self, qaddr):
        res = dns.resolver.Resolver()
        res.nameservers = ["94.140.14.14", "94.140.15.15"]

        try:
            return res.resolve(qaddr)
        except Exception:
            self.debug(f"Unable to resolve {qaddr}")

        return None

    def queryFamilyDNS(self, qaddr):
        res = dns.resolver.Resolver()
        res.nameservers = ["94.140.14.15", "94.140.15.16"]

        try:
            return res.resolve(qaddr)
        except Exception:
            self.debug(f"Unable to resolve {qaddr}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventName == "INTERNET_NAME":
            blacklist_type = "BLACKLISTED_INTERNET_NAME"
        elif eventName == "AFFILIATE_INTERNET_NAME":
            blacklist_type = "BLACKLISTED_AFFILIATE_INTERNET_NAME"
        elif eventName == "CO_HOSTED_SITE":
            blacklist_type = "BLACKLISTED_COHOST"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        family = self.GhostOsint.normalizeDNS(self.queryFamilyDNS(eventData))
        default = self.GhostOsint.normalizeDNS(self.queryDefaultDNS(eventData))

        if not family or not default:
            return

        if '94.140.14.35' in family:
            self.debug(f"{eventData} blocked by AdGuard Family DNS")
            evt = GhostOsintEvent(blacklist_type, f"AdGuard - Family Filter [{eventData}]", self.__name__, event)
            self.notifyListeners(evt)

        if '94.140.14.35' in default:
            self.debug(f"{eventData} blocked by AdGuard Default DNS")
            evt = GhostOsintEvent(blacklist_type, f"AdGuard - Default Filter [{eventData}]", self.__name__, event)
            self.notifyListeners(evt)

# End of GO_adguard_dns class
