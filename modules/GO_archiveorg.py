# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_archiveorg
# Purpose:      Queries archive.org (Wayback machine) for historic versions of
#               certain pages.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/07/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import datetime
import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_archiveorg(GhostOsintPlugin):

    meta = {
        'name': "Archive 互联网档案馆",
        'summary': "识别来自 Wayback Machine 有趣文件和历史版本.",
        'flags': ["slow"],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://archive.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://archive.org/projects/",
                "https://archive.org/services/docs/api/"
            ],
            'favIcon': "https://archive.org/images/glogo.jpg",
            'logo': "https://archive.org/images/glogo.jpg",
            'description': "Internet Archive is a non-profit library of millions of free books, movies, software, music, websites, and more.\n"
            "The Internet Archive, a 501(c)(3) non-profit, is building a digital library of Internet sites "
            "and other cultural artifacts in digital form. Like a paper library, we provide free access to "
            "researchers, historians, scholars, the print disabled, and the general public. "
            "Our mission is to provide Universal Access to All Knowledge.\n"
            "We began in 1996 by archiving the Internet itself, a medium that was just beginning to grow in use. "
            "Like newspapers, the content published on the web was ephemeral - but unlike newspapers, no one was saving it. "
            "Today we have 20+ years of web history accessible through the Wayback Machine and we work with 625+ library and "
            "other partners through our Archive-It program to identify important web pages.",
        }

    }

    # Default options
    opts = {
        'farback': "30,60,90",
        'intfiles': True,
        'passwordpages': True,
        'formpages': False,
        'flashpages': False,
        'javapages': False,
        'staticpages': False,
        'uploadpages': False,
        'webframeworkpages': False,
        'javascriptpages': False
    }

    # Option descriptions
    optdescs = {
        'farback': "在 Wayback Machine 快照中查找旧版本文件/页面的返回天数. 以逗号分隔这些值，例如，30，60，90表示查找30天、60天和90天前的快照.",
        'intfiles': "向 Wayback Machine 查询感兴趣文件的历史版本.",
        'passwordpages': "向 Wayback Machine 查询带有密码的URL地址的历史版本.",
        'formpages': "在 Wayback Machine 中查询带有表单的URL地址的历史版本.",
        'uploadpages': "向 Wayback Machine 查询接受上传的URL地址的历史版本.",
        'flashpages': "在Wayback Machine中查询包含Flash的URL地址的历史版本.",
        'javapages': "使用 Java 小程序向 Wayback Machine 查询URL地址的历史版本.",
        'staticpages': "向 Wayback Machine 查询纯静态URL地址的历史版本.",
        "webframeworkpages": "使用 JavaScript 框架在 Wayback Machine 上查询URL地址的历史版本.",
        "javascriptpages": "使用 JavaScript 框架向 Wayback Machine 查询URL地址的历史版本."
    }

    results = None
    foundDates = list()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.foundDates = list()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERESTING_FILE", "URL_PASSWORD", "URL_FORM", "URL_FLASH",
                "URL_STATIC", "URL_JAVA_APPLET", "URL_UPLOAD", "URL_JAVASCRIPT",
                "URL_WEB_FRAMEWORK"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["INTERESTING_FILE_HISTORIC", "URL_PASSWORD_HISTORIC",
                "URL_FORM_HISTORIC", "URL_FLASH_HISTORIC",
                "URL_STATIC_HISTORIC", "URL_JAVA_APPLET_HISTORIC",
                "URL_UPLOAD_HISTORIC", "URL_WEB_FRAMEWORK_HISTORIC",
                "URL_JAVASCRIPT_HISTORIC"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName == "INTERESTING_FILE" and not self.opts['intfiles']:
            return
        if eventName == "URL_PASSWORD" and not self.opts['passwordpages']:
            return
        if eventName == "URL_STATIC" and not self.opts['staticpages']:
            return
        if eventName == "URL_FORM" and not self.opts['formpages']:
            return
        if eventName == "URL_UPLOAD" and not self.opts['uploadpages']:
            return
        if eventName == "URL_JAVA_APPLET" and not self.opts['javapages']:
            return
        if eventName == "URL_FLASH" and not self.opts['flashpages']:
            return
        if eventName == "URL_JAVASCRIPT" and not self.opts['javascriptpages']:
            return
        if eventName == "URL_WEB_FRAMEWORK" and not self.opts['webframeworkpages']:
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        for daysback in self.opts['farback'].split(","):
            try:
                newDate = datetime.datetime.now() - datetime.timedelta(days=int(daysback))
            except Exception:
                self.error("Unable to parse option for number of days back to search.")
                self.errorState = True
                return

            maxDate = newDate.strftime("%Y%m%d")

            url = "https://archive.org/wayback/available?url=" + eventData + \
                  "&timestamp=" + maxDate
            res = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])

            if res['content'] is None:
                self.error(f"Unable to fetch {url}")
                continue

            try:
                ret = json.loads(res['content'])
            except Exception as e:
                self.debug(f"Error processing JSON response from Archive.org: {e}")
                ret = None

            if not ret:
                self.debug(f"Empty response from archive.org for {eventData}")
                continue

            if len(ret['archived_snapshots']) < 1:
                self.debug("No archived snapshots for " + eventData)
                continue

            wbmlink = ret['archived_snapshots']['closest']['url']
            if wbmlink in self.foundDates:
                self.debug("Snapshot already fetched.")
                continue

            self.foundDates.append(wbmlink)
            name = eventName + "_HISTORIC"

            self.info("Found a historic file: " + wbmlink)
            evt = GhostOsintEvent(name, wbmlink, self.__name__, event)
            self.notifyListeners(evt)

# End of GO_archiveorg class
