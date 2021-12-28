# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_hosting
# Purpose:      GhostOSINT plug-in for looking up whether IPs/Netblocks/Domains
#               appear in an IP categorization table of hosting providers.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     16/08/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_hosting(GhostOsintPlugin):

    meta = {
        'name': "Hosting Provider Identifier",
        'summary': "Find out if any IP addresses identified fall within known 3rd party hosting ranges, e.g. Amazon, Azure, etc.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    # Target
    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "DNS"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["PROVIDER_HOSTING"]

    def queryAddr(self, qaddr):
        data = dict()
        url = "https://raw.githubusercontent.com/client9/ipcat/master/datacenters.csv"

        data['content'] = self.GhostOsint.cacheGet("sfipcat", 48)
        if data['content'] is None:
            data = self.GhostOsint.fetchUrl(url, useragent=self.opts['_useragent'])
            if data['content'] is None:
                self.error("Unable to fetch " + url)
                return None
            else:
                self.GhostOsint.cachePut("sfipcat", data['content'])

        for line in data['content'].split('\n'):
            if "," not in line:
                continue
            try:
                [start, end, title, url] = line.split(",")
            except Exception:
                continue

            try:
                if IPAddress(qaddr) > IPAddress(start) and IPAddress(qaddr) < IPAddress(end):
                    return [title, url]
            except Exception as e:
                self.debug("Encountered an issue processing an IP: " + str(e))
                continue

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        ret = self.queryAddr(eventData)
        if ret:
            evt = GhostOsintEvent("PROVIDER_HOSTING", ret[0] + ": " + ret[1],
                                  self.__name__, event)
            self.notifyListeners(evt)

# End of GO_hosting class
