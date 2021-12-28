# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_iban
# Purpose:      GhostOSINT plug-in for scanning retrieved content by other
#               modules (such as GO_spider) and identifying IBANs.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     26/04/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_iban(GhostOsintPlugin):

    meta = {
        'name': "IBAN Number Extractor",
        'summary': "Identify International Bank Account Numbers (IBANs) in any data.",
        'flags': ["errorprone"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    opts = {
    }

    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        # Override datasource for GO_iban module
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT", "DARKNET_MENTION_CONTENT",
                "LEAKSITE_CONTENT"]

    # What events this module produces
    def producedEvents(self):
        return ["IBAN_NUMBER"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        ibanNumbers = self.GhostOsint.parseIBANNumbers(eventData)
        for ibanNumber in set(ibanNumbers):
            self.info(f"Found IBAN number: {ibanNumber}")
            evt = GhostOsintEvent("IBAN_NUMBER", ibanNumber, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)

# End of GO_iban class
