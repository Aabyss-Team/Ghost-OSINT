# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_sublist3r
# Purpose:      GhostOSINT plug-in for subdomain enumeration using
#               api.sublist3r.com
#
# Author:      TheTechromancer
#
# Created:     05/21/2021
# Copyright:   (c) Steve Micallef 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_sublist3r(GhostOsintPlugin):

    meta = {
        "name": "Sublist3r PassiveDNS",
        "summary": "Passive subdomain enumeration using Sublist3r's API",
        "useCases": ["Investigate", "Footprint", "Passive"],
        "categories": ["Passive DNS"],
        "dataSource": {
            "website": "https://api.sublist3r.com",
            "model": "FREE_NOAUTH_UNLIMITED",
            "description": "This is the API queried by the Sublist3r tool.",
        }
    }

    # Default options
    opts = {}

    # Option descriptions
    optdescs = {}

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.debug("Setting up GO_sublist3r")
        self.results = self.tempStorage()
        self.opts.update(userOpts)

    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME"]

    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]

    def query(self, domain):
        url = f"https://api.sublist3r.com/search.php?domain={domain}"
        ret = []
        res = self.GhostOsint.fetchUrl(
            url,
            useragent=self.opts.get("_useragent", "ghostosint"),
            # mirror sublist3r's headers
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.8",
                "Accept-Encoding": "gzip",
            }
        )
        try:
            ret = [s.strip().lower() for s in json.loads(res["content"])]
        except json.decoder.JSONDecodeError as e:
            self.error(f"Error decoding JSON response: {e}")
        except TypeError:
            self.error("Error querying Sublist3r API")

        if res["code"] not in ["200"]:
            self.error(f"Bad response code \"{res['code']}\" from Sublist3r API")

        return list(set(ret))

    def sendEvent(self, source, host):
        if self.GhostOsint.resolveHost(host) or self.GhostOsint.resolveHost6(host):
            e = GhostOsintEvent("INTERNET_NAME", host, self.__name__, source)
        else:
            e = GhostOsintEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, source)
        self.notifyListeners(e)

    def handleEvent(self, event):
        query = str(event.data).lower()

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        # skip if we've already processed this event (or its parent domain/subdomain)
        target = self.getTarget()
        eventDataHash = self.GhostOsint.hashstring(query)
        if eventDataHash in self.results or \
                (target.matches(query, includeParents=True) and not
                 target.matches(query, includeChildren=False)):
            self.debug(f"Skipping already-processed event, {event.eventType}, from {event.module}")
            return
        self.results[eventDataHash] = True

        for hostname in self.query(query):
            if target.matches(hostname, includeParents=True) and not \
                    target.matches(hostname, includeChildren=False):
                self.sendEvent(event, hostname)
            else:
                self.debug(f"Invalid subdomain: {hostname}")
