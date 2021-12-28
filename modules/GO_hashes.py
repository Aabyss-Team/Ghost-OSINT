# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_hashes
# Purpose:      GhostOSINT plug-in for scanning retrieved content by other
#               modules (such as GO_spider) and identifying hashes
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     24/01/2020
# Copyright:   (c) Steve Micallef 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_hashes(GhostOsintPlugin):

    meta = {
        'name': "Hash Extractor",
        'summary': "Identify MD5 and SHA hashes in web content, files and more.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    # Default options
    opts = {
        # options specific to this module
    }

    # Option descriptions
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT", "BASE64_DATA",
                "LEAKSITE_CONTENT", "RAW_DNS_RECORDS",
                "RAW_FILE_META_DATA"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["HASH"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        hashes = self.GhostOsint.parseHashes(eventData)
        for hashtup in hashes:
            hashalgo, hashval = hashtup

            evt = GhostOsintEvent("HASH", "[" + hashalgo + "] " + hashval, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)

# End of GO_hashes class
