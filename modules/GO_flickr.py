# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_flickr
# Purpose:     Search Flickr API for domains, URLs and emails related to the
#              specified domain.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-08
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_flickr(GhostOsintPlugin):

    meta = {
        'name': "Flickr",
        'summary': "在 Flickr 中所与指定域名相关的域名、Url地址和电子邮件.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://www.flickr.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.flickr.com/services/api/",
                "https://www.flickr.com/services/developer/api/",
                "https://code.flickr.net/"
            ],
            'favIcon': "https://combo.staticflickr.com/pw/favicon.ico",
            'logo': "https://combo.staticflickr.com/pw/favicon.ico",
            'description': "Flickr 几乎可以肯定是世界上最好的在线照片管理和共享应用程序.\n "
                           "在Flickr上，会员上传照片，安全地共享照片，使用元数据（如许可证信息、地理位置、人员、标签等）补充照片，"
                           "并与家人、朋友、联系人或社区中的任何人进行互动. "
                           "实际上，Flickr各种平台上的所有功能——web、移动和桌面——都伴随着一个长期存在的API程序. "
                           "自2005年以来，开发人员在Flickr的API之上进行合作，围绕照片构建有趣、创意和华丽的体验，这些体验超越了Flickr.",
        }
    }

    # Default options
    opts = {
        'pause': 1,
        'per_page': 100,
        'maxpages': 20,
        'dns_resolve': True,
    }

    # Option descriptions
    optdescs = {
        'pause': "读取之间暂停的秒数.",
        'per_page': "每页最大结果数.",
        'maxpages': "提取结果最大页数.",
        'dns_resolve': "DNS解析每个已识别到的域.",
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR", "EMAILADDR_GENERIC", "INTERNET_NAME",
                "DOMAIN_NAME", "LINKED_URL_INTERNAL"]

    # Retrieve API key
    def retrieveApiKey(self):
        res = self.GhostOsint.fetchUrl("https://www.flickr.com/", timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            return None

        keys = re.findall(r'YUI_config.flickr.api.site_key = "([a-zA-Z0-9]+)"', str(res['content']))

        if not keys:
            return None

        return keys[0]

    # Query the REST API
    def query(self, qry, api_key, page=1, per_page=200):
        params = {
            "sort": "relevance",
            "parse_tags": "1",
            "content_type": "7",
            "extras": "description,owner_name,path_alias,realname",
            "hermes": "1",
            "hermesClient": "1",
            "reqId": "",
            "nojsoncallback": "1",
            "viewerNSID": "",
            "method": "flickr.photos.search",
            "csrf": "",
            "lang": "en-US",
            "per_page": str(per_page),
            "page": str(page),
            "text": qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            "api_key": api_key,
            "format": "json"
        }

        res = self.GhostOsint.fetchUrl("https://api.flickr.com/services/rest?" + urllib.parse.urlencode(params),
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        time.sleep(self.opts['pause'])

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked")
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if srcModuleName == 'GO_flickr':
            self.debug(f"Ignoring {eventData}, from self.")
            return

        # Retrieve API key
        api_key = self.retrieveApiKey()

        if not api_key:
            self.error("Failed to obtain API key")
            return

        self.debug(f"Retrieved API key: {api_key}")

        # Query API for event data
        hosts = list()
        page = 1
        pages = self.opts['maxpages']
        per_page = self.opts['per_page']
        while page <= pages:
            if self.checkForStop():
                return

            if self.errorState:
                return

            data = self.query(eventData, api_key, page=page, per_page=per_page)

            if data is None:
                return

            # Check the response is ok
            if data.get('stat') != "ok":
                self.debug("Error retrieving search results.")
                return

            photos = data.get('photos')

            if not photos:
                self.debug("No search results.")
                return

            # Calculate number of pages to retrieve
            result_pages = int(photos.get('pages', 0))

            if result_pages < pages:
                pages = result_pages

            if 'max_allowed_pages' in photos:
                allowed_pages = int(photos.get('max_allowed_pages', 0))
                if pages > allowed_pages:
                    pages = allowed_pages

            self.info(f"Parsing page {page} of {pages}")

            # Extract data
            for photo in photos.get('photo', list()):
                emails = self.GhostOsint.parseEmails(str(photo))
                for email in emails:
                    if email in self.results:
                        continue

                    mail_domain = email.lower().split('@')[1]

                    if not self.getTarget().matches(mail_domain, includeChildren=True, includeParents=True):
                        self.debug(f"Skipped unrelated address: {email}")
                        continue

                    self.info("Found e-mail address: " + email)
                    if email.split("@")[0] in self.opts['_genericusers'].split(","):
                        evttype = "EMAILADDR_GENERIC"
                    else:
                        evttype = "EMAILADDR"

                    evt = GhostOsintEvent(evttype, email, self.__name__, event)
                    self.notifyListeners(evt)
                    self.results[email] = True

                links = self.GhostOsint.extractUrls(str(photo))
                for link in links:
                    if link in self.results:
                        continue

                    host = self.GhostOsint.urlFQDN(link)

                    if not self.getTarget().matches(host, includeChildren=True, includeParents=True):
                        self.debug(f"Skipped unrelated URL: {link}")
                        continue

                    hosts.append(host)

                    self.debug(f"Found a URL: {link}")
                    evt = GhostOsintEvent('LINKED_URL_INTERNAL', link, self.__name__, event)
                    self.notifyListeners(evt)
                    self.results[link] = True

            page += 1

        for host in set(hosts):
            if self.checkForStop():
                return

            if self.errorState:
                return

            if self.opts['dns_resolve'] and not self.GhostOsint.resolveHost(host) and not self.GhostOsint.resolveHost6(host):
                self.debug(f"Host {host} could not be resolved")
                evt = GhostOsintEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, event)
                self.notifyListeners(evt)
                continue

            evt = GhostOsintEvent("INTERNET_NAME", host, self.__name__, event)
            self.notifyListeners(evt)
            if self.GhostOsint.isDomain(host, self.opts["_internettlds"]):
                evt = GhostOsintEvent("DOMAIN_NAME", host, self.__name__, event)
                self.notifyListeners(evt)

# End of GO_flickr class
