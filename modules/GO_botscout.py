# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_botscout
# Purpose:      GhostOSINT plug-in to search botsout.com using their API, for
#               potential malicious IPs and e-mail addresses.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     25/07/2016
# Copyright:   (c) Steve Micallef 2016
# Licence:     GPL
# -------------------------------------------------------------------------------

import urllib.error
import urllib.parse
import urllib.request

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_botscout(GhostOsintPlugin):

    meta = {
        'name': "BotScout",
        'summary': "Searches BotScout.com's database of spam-bot IP addresses and e-mail addresses.",
        'flags': ["apikey"],
        'useCases': ["Passive", "Investigate"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://botscout.com/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "http://botscout.com/api.htm",
                "http://botscout.com/api_queries.htm",
                "http://botscout.com/getkey.htm",
                "http://botscout.com/corp_users.htm"
            ],
            'apiKeyInstructions': [
                "Visit http://botscout.com/getkey.htm",
                "Register a free account",
                "The API key will be emailed to your account"
            ],
            'favIcon': "https://botscout.com/favicon.ico",
            'logo': "http://botscout.com/image/bslogo.gif",
            'description': "BotScout helps prevent automated web scripts, known as \"bots\", "
            "from registering on forums, polluting databases, spreading spam, "
            "and abusing forms on web sites. We do this by tracking the names, IPs, "
            "and email addresses that bots use and logging them as unique signatures for future reference. "
            "We also provide a simple yet powerful API that you can use to test forms "
            "when they're submitted on your site.",
        }
    }

    opts = {
        "api_key": ""
    }
    optdescs = {
        "api_key": "Botscout.com API key. Without this you will be limited to 100 look-ups per day."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['IP_ADDRESS', 'EMAILADDR']

    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "BLACKLISTED_IPADDR", "MALICIOUS_EMAILADDR"]

    def queryIp(self, ip):
        if not self.GhostOsint.validIP(ip):
            return None

        params = urllib.parse.urlencode({
            'ip': ip,
            'key': self.opts['api_key'],
        })

        res = self.GhostOsint.fetchUrl(
            f"https://botscout.com/test/?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        return self.parseApiResponse(res)

    def queryEmail(self, email):
        if not self.GhostOsint.validEmail(email):
            return None

        params = urllib.parse.urlencode({
            'mail': email,
            'key': self.opts['api_key'],
        })

        res = self.GhostOsint.fetchUrl(
            f"https://botscout.com/test/?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        return self.parseApiResponse(res)

    def parseApiResponse(self, res):
        if not res['content']:
            self.error("No response from BotScout.")
            return None

        if res['content'].startswith("! "):
            self.error(f"Received error from BotScout: {res['content']}")
            self.errorState = True
            return None

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from BotScout.")
            self.errorState = True
            return None

        if not res['content'].startswith("Y|") and not res['content'].startswith("N|"):
            self.error("Error encountered processing response from BotScout.")
            return None

        return res['content']

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if not self.opts['api_key']:
            self.info("You enabled GO_botscout but did not set an API key! Queries will be limited to 100 per day.")

        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already searched.")
            return

        self.results[eventData] = True

        if eventName == "IP_ADDRESS":
            res = self.queryIp(eventData)

            if not res:
                return

            if not res.startswith("Y|"):
                return

            self.info(f"Found BotScout entry for {eventData}: {res}")

            url = f"https://botscout.com/ipcheck.htm?ip={eventData}"
            text = f"BotScout [{eventData}]\n<SFURL>{url}</SFURL>"

            evt = GhostOsintEvent("MALICIOUS_IPADDR", text, self.__name__, event)
            self.notifyListeners(evt)

            evt = GhostOsintEvent("BLACKLISTED_IPADDR", text, self.__name__, event)
            self.notifyListeners(evt)
        elif eventName == "EMAILADDR":
            res = self.queryEmail(eventData)

            if not res:
                return

            if not res.startswith("Y|"):
                return

            url = f"https://botscout.com/search.htm?sterm={eventData}&stype=q"
            text = f"BotScout [{eventData}]\n<SFURL>{url}</SFURL>"

            evt = GhostOsintEvent("MALICIOUS_EMAILADDR", text, self.__name__, event)
            self.notifyListeners(evt)
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")

# End of GO_botscout class
