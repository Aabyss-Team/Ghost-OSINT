# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_arin
# Purpose:      Queries the ARIN internet registry to get netblocks and other
#               bits of info.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     23/02/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_arin(GhostOsintPlugin):

    meta = {
        'name': "ARIN",
        'summary': "Queries ARIN registry for contact information.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://www.arin.net/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.arin.net/resources/",
                "https://www.arin.net/reference/",
                "https://www.arin.net/participate/",
                "https://www.arin.net/resources/guide/request/",
                "https://www.arin.net/resources/registry/transfers/",
                "https://www.arin.net/resources/guide/ipv6/"
            ],
            'favIcon': "https://www.arin.net/img/favicon.ico",
            'logo': "https://www.arin.net/img/logo-stnd.svg",
            'description': "ARIN is a nonprofit, member-based organization that administers IP addresses & "
            "ASNs in support of the operation and growth of the Internet.\n"
            "Established in December 1997 as a Regional Internet Registry, "
            "the American Registry for Internet Numbers (ARIN) is responsible for the management "
            "and distribution of Internet number resources such as Internet Protocol (IP) addresses "
            "and Autonomous System Numbers (ASNs). ARIN manages these resources within its service region, "
            "which is comprised of Canada, the United States, and many Caribbean and North Atlantic islands.",
        }
    }

    # Default options
    opts = {}
    optdescs = {}

    results = None
    currentEventSrc = None
    keywords = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.currentEventSrc = None

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['DOMAIN_NAME', 'HUMAN_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["RAW_RIR_DATA"]

    # Fetch content and notify of the raw data
    def fetchRir(self, url):
        head = {"Accept": "application/json"}
        res = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'], headers=head)
        if res['content'] is not None and res['code'] != "404":
            return res
        return None

    # Owner information about an AS
    def query(self, qtype, value):
        url = "https://whois.arin.net/rest/"

        if qtype == "domain":
            url += "pocs;domain=@" + value

        try:
            if qtype == "name":
                fname, lname = value.split(" ", 1)
                if fname.endswith(","):
                    t = fname
                    fname = lname
                    lname = t
                url += "pocs;first=" + fname + ";last=" + lname
        except Exception as e:
            self.debug("Couldn't process name: " + value + " (" + str(e) + ")")
            return None

        if qtype == "contact":
            url = value

        res = self.fetchRir(url)
        if not res:
            self.debug("No info found/available for " + value + " at ARIN.")
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        evt = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, self.currentEventSrc)
        self.notifyListeners(evt)
        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "DOMAIN_NAME":
            ret = self.query("domain", eventData)
            if not ret:
                return
            if "pocs" in ret:
                if "pocRef" in ret['pocs']:
                    ref = list()
                    # Might be a list or a dictionary
                    if type(ret['pocs']['pocRef']) == dict:
                        ref = [ret['pocs']['pocRef']]
                    else:
                        ref = ret['pocs']['pocRef']
                    for p in ref:
                        name = p['@name']
                        if "," in name:
                            sname = name.split(", ", 1)
                            name = sname[1] + " " + sname[0]

                        # A bit of a hack. The reason we do this is because
                        # the names are separated in the content and GO_names
                        # won't recognise it. So we submit this and see if it
                        # really is considered a name.
                        evt = GhostOsintEvent("RAW_RIR_DATA", "Possible full name: " + name,
                                              self.__name__, self.currentEventSrc)
                        self.notifyListeners(evt)

                        # We just want the raw data so we can get potential
                        # e-mail addresses.
                        self.query("contact", p['$'])

        if eventName == "HUMAN_NAME":
            ret = self.query("name", eventData)
            if not ret:
                return
            if "pocs" in ret:
                if "pocRef" in ret['pocs']:
                    ref = list()
                    # Might be a list or a dictionary
                    if type(ret['pocs']['pocRef']) == dict:
                        ref = [ret['pocs']['pocRef']]
                    else:
                        ref = ret['pocs']['pocRef']
                    for p in ref:
                        # We just want the raw data so we can get potential
                        # e-mail addresses.
                        self.query("contact", p['$'])

# End of GO_arin class
