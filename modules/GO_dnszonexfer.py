# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_dnszonexfer
# Purpose:      GhostOSINT plug-in for attempting a DNS zone transfer.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     22/08/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

import dns.query
import dns.zone

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_dnszonexfer(GhostOsintPlugin):

    meta = {
        'name': "DNS Zone Transfer",
        'summary': "Attempts to perform a full DNS zone transfer.",
        'flags': [],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["DNS"]
    }

    opts = {
        "timeout": 30
    }

    optdescs = {
        "timeout": "Timeout in seconds"
    }

    events = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.events = self.tempStorage()
        self.__dataSource__ = "DNS"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['PROVIDER_DNS']

    def producedEvents(self):
        return ["RAW_DNS_RECORDS", "INTERNET_NAME"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventDataHash = self.GhostOsint.hashstring(eventData)
        parentEvent = event

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if srcModuleName == "GO_dnszonexfer":
            self.debug(f"Ignoring {eventName}, from self.")
            return

        if eventDataHash in self.events:
            self.debug("Skipping duplicate event for " + eventData)
            return

        self.events[eventDataHash] = True

        res = dns.resolver.Resolver()
        if self.opts.get('_dnsserver', "") != "":
            res.nameservers = [self.opts['_dnsserver']]

        # Get the name server's IP. This is to avoid DNS leaks
        # when attempting to resolve the name server during
        # the zone transfer.
        if not self.GhostOsint.validIP(eventData) and not self.GhostOsint.validIP6(eventData):
            nsips = self.GhostOsint.resolveHost(eventData)
            if not nsips:
                return

            if not nsips:
                self.error("Couldn't resolve the name server, so not attempting zone transfer.")
                return

            for n in nsips:
                if self.GhostOsint.validIP(n):
                    nsip = n
                    break
        else:
            nsip = eventData

        for name in self.getTarget().getNames():
            self.debug("Trying for name: " + name)
            try:
                ret = list()
                z = dns.zone.from_xfr(dns.query.xfr(nsip, name, timeout=int(self.opts["timeout"])))
                names = list(z.nodes.keys())
                for n in names:
                    ret.append(z[n].to_text(n))

                evt = GhostOsintEvent("RAW_DNS_RECORDS", "\n".join(ret), self.__name__, parentEvent)
                self.notifyListeners(evt)

                # Try and pull out individual records
                for row in ret:
                    pat = re.compile(r"^(\S+)\.?\s+\d+\s+IN\s+[AC].*", re.IGNORECASE | re.DOTALL)
                    grps = re.findall(pat, row)
                    if len(grps) > 0:
                        for strdata in grps:
                            self.debug("Matched: " + strdata)
                            if strdata.endswith("."):
                                strdata = strdata[:-1]
                            else:
                                strdata = strdata + "." + name

                            evt = GhostOsintEvent("INTERNET_NAME", strdata, self.__name__, parentEvent)
                            self.notifyListeners(evt)

            except Exception as e:
                self.info(f"Unable to perform DNS zone transfer for {eventData} ({name}): {e}")

# End of GO_dnszonexfer class
