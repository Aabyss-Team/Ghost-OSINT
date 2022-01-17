# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_stor_db
# Purpose:      GhostOSINT plugin for storing events to the local GhostOSINT
#               SQLite database.
# -------------------------------------------------------------------------------

from ghostosint import GhostOsintPlugin


class GO__stor_db(GhostOsintPlugin):

    meta = {
        'name': "存储",
        'summary': "将扫描结果储存到 GhostOSINT 数据库中."
    }

    _priority = 0

    # Default options
    opts = {
        'maxstorage': 1024,  # max bytes for any piece of info stored (0 = 无限)
        '_store': True
    }

    # Option descriptions
    optdescs = {
        'maxstorage': "为检索到的任何信息储存最大字节数 (0 为无限.)"
    }

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # Because this is a storage plugin, we are interested in everything so we
    # can store all events for later analysis.
    def watchedEvents(self):
        return ["*"]

    # Handle events sent to this module
    def handleEvent(self, GOEvent):
        if not self.opts['_store']:
            return

        if self.opts['maxstorage'] != 0:
            if len(GOEvent.data) > self.opts['maxstorage']:
                self.debug("Storing an event: " + GOEvent.eventType)
                self.__GODB__.scanEventStore(self.getScanId(), GOEvent, self.opts['maxstorage'])
                return

        self.debug("Storing an event: " + GOEvent.eventType)
        self.__GODB__.scanEventStore(self.getScanId(), GOEvent)

# End of GO__stor_db class
