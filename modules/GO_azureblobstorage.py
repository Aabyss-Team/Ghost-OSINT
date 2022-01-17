# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_azureblobstorage
# Purpose:      GhostOSINT plug-in for identifying potential Azure blobs related
#               to the target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     14/07/2019
# Copyright:   (c) Steve Micallef 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import random
import threading
import time

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_azureblobstorage(GhostOsintPlugin):

    meta = {
        'name': "Azure Blob 存储查找",
        'summary': "搜索与目标关联的潜在Azure Blob 存储并列出其内容.",
        'flags': [],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://azure.microsoft.com/en-in/services/storage/blobs/",
            'model': "FREE_NOAUTH_UNLIMITED"
        }
    }

    # Default options
    opts = {
        "suffixes": "test,dev,web,beta,bucket,space,files,content,data,prod,staging,production,stage,app,media,development,-test,-dev,-web,-beta,-bucket,-space,-files,-content,-data,-prod,-staging,-production,-stage,-app,-media,-development",
        "_maxthreads": 20
    }

    # Option descriptions
    optdescs = {
        "suffixes": "要作为 Blob 存储名称附加到域的后缀列表",
        "_maxthreads": "最大线程数"
    }

    results = None
    s3results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.s3results = self.tempStorage()
        self.results = self.tempStorage()
        self.lock = threading.Lock()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "LINKED_URL_EXTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["CLOUD_STORAGE_BUCKET"]

    def checkSite(self, url):
        res = self.GhostOsint.fetchUrl(url, timeout=10, useragent="GhostOSINT", noLog=True)

        if res['code']:
            with self.lock:
                self.s3results[url] = True

    def threadSites(self, siteList):
        self.s3results = dict()
        running = True
        i = 0
        t = []

        for site in siteList:
            if self.checkForStop():
                return None

            self.info("Spawning thread to check bucket: " + site)
            tname = str(random.SystemRandom().randint(0, 999999999))
            t.append(threading.Thread(name='thread_GO_azureblobstorages_' + tname,
                                      target=self.checkSite, args=(site,)))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("thread_GO_azureblobstorages_"):
                    found = True

            if not found:
                running = False

            time.sleep(0.25)

        # Return once the scanning has completed
        return self.s3results

    def batchSites(self, sites):
        i = 0
        res = list()
        siteList = list()

        for site in sites:
            if i >= self.opts['_maxthreads']:
                data = self.threadSites(siteList)
                if data is None:
                    return res

                for ret in list(data.keys()):
                    if data[ret]:
                        res.append(ret)
                i = 0
                siteList = list()

            siteList.append(site)
            i += 1

        return res

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName == "LINKED_URL_EXTERNAL":
            if ".blob.core.windows.net" in eventData:
                b = self.GhostOsint.urlFQDN(eventData)
                evt = GhostOsintEvent("CLOUD_STORAGE_BUCKET", b, self.__name__, event)
                self.notifyListeners(evt)
            return

        targets = [eventData.replace('.', '')]
        kw = self.GhostOsint.domainKeyword(eventData, self.opts['_internettlds'])
        if kw:
            targets.append(kw)

        urls = list()
        for t in targets:
            suffixes = [''] + self.opts['suffixes'].split(',')
            for s in suffixes:
                if self.checkForStop():
                    return

                b = t + s + ".blob.core.windows.net"
                url = "https://" + b
                urls.append(url)

        # Batch the scans
        ret = self.batchSites(urls)
        for b in ret:
            evt = GhostOsintEvent("CLOUD_STORAGE_BUCKET", b, self.__name__, event)
            self.notifyListeners(evt)

# End of GO_azureblobstorage class
