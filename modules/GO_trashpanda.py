# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_trashpanda
# Purpose:      ghostosint plugin to query Trashpanda - got-hacked.wtf API to gather intelligence about
#               mentions of your target in paste sites like Pastebin, Ghostbin and Zeropaste
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     17/04/2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import base64
import json
import re

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_trashpanda(GhostOsintPlugin):

    meta = {
        'name': "Trashpanda",
        'summary': "查询 Trashpanda 以收集有关项目中提及目标的情报",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://got-hacked.wtf",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "http://api.got-hacked.wtf:5580/help"
            ],
            'apiKeyInstructions': [
                "遵循指南 https://got-hacked.wtf/"
            ],
            'favIcon': "https://got-hacked.wtf/wp-content/uploads/2020/07/cropped-IMG_7619.jpg",
            'logo': "https://got-hacked.wtf/wp-content/uploads/2020/07/cropped-IMG_7619.jpg",
            'description': "该 bot 搜索不同的粘贴站点以查找泄漏的凭据."
            "API本身允许访问bot检测到的所有唯一凭据.",
        }
    }

    # Default options
    opts = {
        'api_key_username': '',
        'api_key_password': '',
    }

    # Option descriptions
    optdescs = {
        'api_key_username': "Trashpanda API 用户名",
        'api_key_password': 'Trashpanda API 密码',
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
            "DOMAIN_NAME",
            "INTERNET_NAME",
            "EMAILADDR"
        ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [
            "LEAKSITE_CONTENT",
            "LEAKSITE_URL",
            "PASSWORD_COMPROMISED",
        ]

    def query(self, qry, eventName):
        secret = self.opts['api_key_username'] + ':' + self.opts['api_key_password']
        auth = base64.b64encode(secret.encode('utf-8')).decode('utf-8')

        queryString = ""
        if eventName in ['DOMAIN_NAME', 'INTERNET_NAME']:
            queryString = f"http://api.got-hacked.wtf:5580/domain?v={qry}&s=zpg"
        elif eventName == "EMAILADDR":
            queryString = f"http://api.got-hacked.wtf:5580/email?v={qry}&s=zpg"

        headers = {
            'Accept': "application/json",
            'Authorization': f"Basic {auth}"
        }

        res = self.GhostOsint.fetchUrl(
            queryString,
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        if res['code'] != "200":
            self.error("Error retrieving search results from Trashpanda(got-hacked.wtf)")
            return None

        return json.loads(res['content'])

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if self.opts['api_key_username'] == "" or self.opts['api_key_password'] == "":
            self.error("You enabled GO_trashpanda but did not set an API username / password!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData, eventName)

        if data is None:
            return

        leaksiteUrls = set()
        for row in data:
            evt = GhostOsintEvent("PASSWORD_COMPROMISED", f"{row.get('email')}:{row.get('password')} [{row.get('paste')}]", self.__name__, event)
            self.notifyListeners(evt)

            leaksiteUrls.add(row.get("paste"))

        for leaksiteUrl in leaksiteUrls:
            try:
                self.debug("Found a link: " + leaksiteUrl)

                if self.checkForStop():
                    return

                res = self.GhostOsint.fetchUrl(leaksiteUrl, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.debug(f"Ignoring {leaksiteUrl} as no data returned")
                    continue

                if re.search(
                    r"[^a-zA-Z\-\_0-9]" + re.escape(eventData) + r"[^a-zA-Z\-\_0-9]",
                    res['content'],
                    re.IGNORECASE
                ) is None:
                    continue

                evt = GhostOsintEvent("LEAKSITE_URL", leaksiteUrl, self.__name__, event)
                self.notifyListeners(evt)

                evt = GhostOsintEvent("LEAKSITE_CONTENT", res['content'], self.__name__, evt)
                self.notifyListeners(evt)
            except Exception as e:
                self.debug(f"Error while fetching leaksite content : {str(e)}")

# End of GO_trashpanda class
