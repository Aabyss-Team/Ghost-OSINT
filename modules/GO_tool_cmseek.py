# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_tool_cmseek
# Purpose:      GhostOSINT plug-in for using the 'CMSeeK' tool.
#               Tool: https://github.com/Tuhinshubhra/CMSeeK
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     16/12/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import io
import json
import os.path
from subprocess import PIPE, Popen

from ghostosint import GhostOsintEvent, GhostOsintPlugin, GhostOsintHelp


class GO_tool_cmseek(GhostOsintPlugin):

    meta = {
        'name': "CMSeeK - 工具",
        'summary': "确定可能使用的内容管理系统(CMS).",
        'flags': ["tool"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Content Analysis"],
        'toolDetails': {
            'name': "CMSeeK",
            'description': "CMSeek 是一种用于提取网站内容管理系统(CMS)详细信息的工具.",
            'website': 'https://github.com/Tuhinshubhra/CMSeeK',
            'repository': 'https://github.com/Tuhinshubhra/CMSeeK'
        },
    }

    # Default options
    opts = {
        'pythonpath': "python3",
        'cmseekpath': ""
    }

    # Option descriptions
    optdescs = {
        'pythonpath': "用于 CMSeek 的 Python 3解释器的路径. 如果只有'Python3'，那么它一定在你的路径中.",
        'cmseekpath': "cmseek.py 文件所在的的路径. 必须设置."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['INTERNET_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["WEBSERVER_TECHNOLOGY"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already scanned.")
            return

        self.results[eventData] = True

        if not self.opts['cmseekpath']:
            self.error("You enabled GO_tool_cmseek but did not set a path to the tool!")
            self.errorState = True
            return

        # Normalize path
        if self.opts['cmseekpath'].endswith('cmseek.py'):
            exe = self.opts['cmseekpath']
            resultpath = self.opts['cmseekpath'].split("cmseek.py")[0] + "/Result"
        elif self.opts['cmseekpath'].endswith('/'):
            exe = self.opts['cmseekpath'] + "cmseek.py"
            resultpath = self.opts['cmseekpath'] + "Result"
        else:
            exe = self.opts['cmseekpath'] + "/cmseek.py"
            resultpath = self.opts['cmseekpath'] + "/Result"

        # If tool is not found, abort
        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        # Sanitize domain name.
        if not GhostOsintHelp.sanitiseInput(eventData):
            self.error("Invalid input, refusing to run.")
            return

        args = [
            self.opts['pythonpath'],
            exe,
            '--follow-redirect',
            '--batch',
            '-u',
            eventData
        ]
        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
        except Exception as e:
            self.error(f"Unable to run CMSeeK: {e}")
            return

        if p.returncode != 0:
            self.error(f"Unable to read CMSeeK output\nstderr: {stderr}\nstdout: {stdout}")
            return

        if b"CMS Detection failed" in stdout:
            self.debug(f"Could not detect the CMS for {eventData}")
            return

        log_path = f"{resultpath}/{eventData}/cms.json"
        if not os.path.isfile(log_path):
            self.error(f"File does not exist: {log_path}")
            return

        try:
            f = io.open(log_path, encoding='utf-8')
            j = json.loads(f.read())
        except Exception as e:
            self.error(f"Could not parse CMSeeK output file {log_path} as JSON: {e}")
            return

        cms_name = j.get('cms_name')

        if not cms_name:
            return

        cms_version = j.get('cms_version')

        software = ' '.join(filter(None, [cms_name, cms_version]))

        if not software:
            return

        evt = GhostOsintEvent("WEBSERVER_TECHNOLOGY", software, self.__name__, event)
        self.notifyListeners(evt)

# End of GO_tool_cmseek class
