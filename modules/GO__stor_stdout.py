# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_stor_stdout
# Purpose:      GhostOSINT plugin for dumping events to standard output.
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintPlugin


class GO__stor_stdout(GhostOsintPlugin):

    meta = {
        'name': "命令行输出",
        'summary': "将内容输出,用于运行命令行Ghost OSINT使用."
    }

    _priority = 0
    firstEvent = True

    # Default options
    opts = {
        "_format": "tab",  # tab, csv, json
        "_requested": [],
        "_showonlyrequested": False,
        "_stripnewline": False,
        "_showsource": False,
        "_csvdelim": ",",
        "_maxlength": 0,
        "_eventtypes": dict()
    }

    # Option descriptions
    optdescs = {
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

    def output(self, event):
        d = self.opts['_csvdelim']
        if type(event.data) in [list, dict]:
            data = str(event.data)
        else:
            data = event.data

        if type(data) != str:
            data = str(event.data)

        if type(event.sourceEvent.data) in [list, dict]:
            srcdata = str(event.sourceEvent.data)
        else:
            srcdata = event.sourceEvent.data

        if type(srcdata) != str:
            srcdata = str(event.sourceEvent.data)

        if self.opts['_stripnewline']:
            data = data.replace("\n", " ").replace("\r", "")
            srcdata = srcdata.replace("\n", " ").replace("\r", "")

        if "<SFURL>" in data:
            data = data.replace("<SFURL>", "").replace("</SFURL>", "")
        if "<SFURL>" in srcdata:
            srcdata = srcdata.replace("<SFURL>", "").replace("</SFURL>", "")

        if self.opts['_maxlength'] > 0:
            data = data[0:self.opts['_maxlength']]
            srcdata = srcdata[0:self.opts['_maxlength']]

        if self.opts['_format'] == "tab":
            if self.opts['_showsource']:
                print(('{0:30}\t{1:45}\t{2}\t{3}'.format(event.module, self.opts['_eventtypes'][event.eventType], srcdata, data)))
            else:
                print(('{0:30}\t{1:45}\t{2}'.format(event.module, self.opts['_eventtypes'][event.eventType], data)))

        if self.opts['_format'] == "csv":
            print((event.module + d + self.opts['_eventtypes'][event.eventType] + d + srcdata + d + data))

        if self.opts['_format'] == "json":
            d = event.asDict()
            d['type'] = self.opts['_eventtypes'][event.eventType]
            if self.firstEvent:
                self.firstEvent = False
            else:
                print(",")
            print(json.dumps(d), end='')

    # Handle events sent to this module
    def handleEvent(self, GOEvent):
        if GOEvent.eventType == "ROOT":
            return

        if self.opts['_showonlyrequested']:
            if GOEvent.eventType in self.opts['_requested']:
                self.output(GOEvent)
        else:
            self.output(GOEvent)

# End of GO__stor_stdout class
