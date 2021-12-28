# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_cookie
# Purpose:      GhostOSINT plug-in for extracting cookies from HTTP headers.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_cookie(GhostOsintPlugin):

    meta = {
        'name': "Cookie Extractor",
        'summary': "Extract Cookies from HTTP headers.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    opts = {}
    optdescs = {}

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["WEBSERVER_HTTPHEADERS"]

    # What events this module produces
    def producedEvents(self):
        return ["TARGET_WEB_COOKIE"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventSource = event.actualSource

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventSource in self.results:
            return

        self.results[eventSource] = True

        fqdn = self.GhostOsint.urlFQDN(eventSource)
        if not self.getTarget().matches(fqdn):
            self.debug(f"Not collecting cookies from external sites. Ignoring HTTP headers from {fqdn}")
            return

        try:
            data = json.loads(eventData)
        except Exception:
            self.error("Received HTTP headers from another module in an unexpected format.")
            return

        cookie = data.get('cookie')
        if cookie:
            evt = GhostOsintEvent("TARGET_WEB_COOKIE", cookie, self.__name__, event)
            self.notifyListeners(evt)

# End of GO_cookie class
