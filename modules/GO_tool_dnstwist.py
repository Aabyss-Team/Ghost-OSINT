# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_tool_dnstwist
# Purpose:      GhostOSINT plug-in for using the 'dnstwist' tool.
#               Tool: https://github.com/elceef/dnstwist
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/11/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from pathlib import Path
from shutil import which
from subprocess import PIPE, Popen

from ghostosint import GhostOsintEvent, GhostOsintPlugin, GhostOsintHelp


class GO_tool_dnstwist(GhostOsintPlugin):

    meta = {
        'name': "DNSTwist - 工具",
        'summary': "使用安装在本地的 DNSTwist 来识别与目标相关的占用、输入错误和其他类似域名.",
        'flags': ["tool"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["DNS"],
        'toolDetails': {
            'name': "DNSTwist",
            'description': "看看用户在尝试键入域名时会遇到什么样的麻烦. "
            "找到敌人可以用来攻击你的相似域名. "
            "可以检测盗用者、网络钓鱼攻击、欺诈和品牌假冒. "
            "作为目标威胁情报的额外来源非常有用.",
            'website': 'https://github.com/elceef/dnstwist',
            'repository': 'https://github.com/elceef/dnstwist'
        },
    }

    # Default options
    opts = {
        'pythonpath': "python",
        'dnstwistpath': ""
    }

    # Option descriptions
    optdescs = {
        'pythonpath': "用于 dnstwist 的 Python 解释器的路径. 如果只是 'Python'，那么它一定在你的路径中.",
        'dnstwistpath': "dnstwist.py 文件所在的路径. 可选."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "DNS"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['DOMAIN_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SIMILARDOMAIN"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if eventData in self.results:
            self.debug("Skipping " + eventData + " as already scanned.")
            return

        self.results[eventData] = True

        dnstwistLocation = which('dnstwist')
        if dnstwistLocation and Path(dnstwistLocation).is_file():
            cmd = ['dnstwist']
        else:
            if not self.opts['dnstwistpath']:
                self.error("You enabled GO_tool_dnstwist but did not set a path to the tool!")
                self.errorState = True
                return

            # Normalize path
            if self.opts['dnstwistpath'].endswith('dnstwist.py'):
                exe = self.opts['dnstwistpath']
            elif self.opts['dnstwistpath'].endswith('/'):
                exe = self.opts['dnstwistpath'] + "dnstwist.py"
            else:
                exe = self.opts['dnstwistpath'] + "/dnstwist.py"

            # If tool is not found, abort
            if not Path(exe).is_file():
                self.error("File does not exist: " + exe)
                self.errorState = True
                return

            cmd = [self.opts['pythonpath'], exe]

        # Sanitize domain name.
        if not GhostOsintHelp.sanitiseInput(eventData):
            self.error("Invalid input, refusing to run.")
            return

        try:
            p = Popen(cmd + ["-f", "json", "-r", eventData], stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
            if p.returncode == 0:
                content = stdout
            else:
                self.error("Unable to read DNSTwist content.")
                self.debug("Error running DNSTwist: " + stderr + ", " + stdout)
                return

            # For each line in output, generate a SIMILARDOMAIN event
            try:
                j = json.loads(content)
                for r in j:
                    if self.getTarget().matches(r['domain-name']):
                        continue

                    evt = GhostOsintEvent("SIMILARDOMAIN", r['domain-name'],
                                          self.__name__, event)
                    self.notifyListeners(evt)
            except Exception as e:
                self.error("Couldn't parse the JSON output of DNSTwist: " + str(e))
                return
        except Exception as e:
            self.error("Unable to run DNSTwist: " + str(e))
            return

# End of GO_tool_dnstwist class
