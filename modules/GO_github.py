# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_github
# Purpose:      Identifies public code repositories in Github associated with
#               your target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     21/07/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_github(GhostOsintPlugin):

    meta = {
        'name': "Github",
        'summary': "在 Github 上识别关联的公共代码库.",
        'flags': [],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Social Media"],
        'dataSource': {
            'website': "https://github.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://developer.github.com/"
            ],
            'favIcon': "https://github.githubassets.com/favicons/favicon.png",
            'logo': "https://github.githubassets.com/favicons/favicon.png",
            'description': "GitHub 汇集了世界上最大的开发者社区，以发现、共享和构建更好的软件.",
        }
    }

    # Default options
    opts = {
        'namesonly': True
    }

    # Option descriptions
    optdescs = {
        'namesonly': "仅按名称而不是按描述来匹配存储库.有助于减少误报."
    }

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "USERNAME", "SOCIAL_MEDIA"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["RAW_RIR_DATA", "GEOINFO", "PUBLIC_CODE_REPO"]

    # Build up repo info for use as an event
    def buildRepoInfo(self, item):
        # Get repos matching the name
        name = item.get('name')
        if name is None:
            self.debug("Incomplete Github information found (name).")
            return None

        html_url = item.get('html_url')
        if html_url is None:
            self.debug("Incomplete Github information found (url).")
            return None

        description = item.get('description')
        if description is None:
            self.debug("Incomplete Github information found (description).")
            return None

        return "\n".join([f"Name: {name}", f"URL: {html_url}", f"Description: {description}"])

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data
        srcModuleName = event.module

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Already did a search for {eventData}, skipping.")
            return

        self.results[eventData] = True

        # Extract name and location from profile
        if eventName == "SOCIAL_MEDIA":
            try:
                network = eventData.split(": ")[0]
                url = eventData.split(": ")[1].replace("<SFURL>", "").replace("</SFURL>", "")
            except Exception as e:
                self.debug(f"Unable to parse SOCIAL_MEDIA: {eventData} ({e})")
                return

            if network != "Github":
                self.debug(f"Skipping social network profile, {url}, as not a GitHub profile")
                return

            try:
                urlParts = url.split("/")
                username = urlParts[len(urlParts) - 1]
            except Exception:
                self.debug(f"Couldn't get a username out of {url}")
                return

            res = self.GhostOsint.fetchUrl(
                f"https://api.github.com/users/{username}",
                timeout=self.opts['_fetchtimeout'],
                useragent=self.opts['_useragent']
            )

            if res['content'] is None:
                return

            try:
                json_data = json.loads(res['content'])
            except Exception as e:
                self.debug(f"Error processing JSON response: {e}")
                return

            if not json_data.get('login'):
                self.debug(f"{username} is not a valid GitHub profile")
                return

            full_name = json_data.get('name')

            if not full_name:
                self.debug(f"{username} is not a valid GitHub profile")
                return

            e = GhostOsintEvent("RAW_RIR_DATA", f"Possible full name: {full_name}", self.__name__, event)
            self.notifyListeners(e)

            location = json_data.get('location')

            if location is None:
                return

            if len(location) < 3 or len(location) > 100:
                self.debug(f"Skipping likely invalid location: {location}")
                return

            e = GhostOsintEvent("GEOINFO", location, self.__name__, event)
            self.notifyListeners(e)

            return

        if eventName == "DOMAIN_NAME":
            username = self.GhostOsint.domainKeyword(eventData, self.opts['_internettlds'])
            if not username:
                return

        if eventName == "USERNAME":
            username = eventData

        self.debug(f"Looking at {username}")
        failed = False

        # Get all the repositories based on direct matches with the
        # name identified
        url = f"https://api.github.com/search/repositories?q={username}"
        res = self.GhostOsint.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.error(f"Unable to fetch {url}")
            failed = True

        if not failed:
            try:
                ret = json.loads(res['content'])
            except Exception as e:
                self.debug(f"Error processing JSON response from GitHub: {e}")
                ret = None

            if ret is None:
                self.error(f"Unable to process empty response from Github for: {username}")
                failed = True

        if not failed:
            if ret.get('total_count', "0") == "0" or len(ret['items']) == 0:
                self.debug(f"No Github information for {username}")
                failed = True

        if not failed:
            for item in ret['items']:
                repo_info = self.buildRepoInfo(item)
                if repo_info is not None:
                    if self.opts['namesonly'] and username != item['name']:
                        continue

                    evt = GhostOsintEvent("PUBLIC_CODE_REPO", repo_info, self.__name__, event)
                    self.notifyListeners(evt)

        # Now look for users matching the name found
        failed = False
        url = f"https://api.github.com/search/users?q={username}"
        res = self.GhostOsint.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['content'] is None:
            self.error(f"Unable to fetch {url}")
            failed = True

        if not failed:
            try:
                ret = json.loads(res['content'])
                if ret is None:
                    self.error(f"Unable to process empty response from Github for: {username}")
                    failed = True
            except Exception:
                self.error(f"Unable to process invalid response from Github for: {username}")
                failed = True

        if not failed:
            if ret.get('total_count', "0") == "0" or len(ret['items']) == 0:
                self.debug("No Github information for " + username)
                failed = True

        if not failed:
            # For each user matching the username, get their repos
            for item in ret['items']:
                if item.get('repos_url') is None:
                    self.debug("Incomplete Github information found (repos_url).")
                    continue

                url = item['repos_url']
                res = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.error(f"Unable to fetch {url}")
                    continue

                try:
                    repret = json.loads(res['content'])
                except Exception as e:
                    self.error(f"Invalid JSON returned from Github: {e}")
                    continue

                if repret is None:
                    self.error(f"Unable to process empty response from Github for: {username}")
                    continue

                for item in repret:
                    if type(item) != dict:
                        self.debug("Encountered an unexpected or empty response from Github.")
                        continue

                    repo_info = self.buildRepoInfo(item)
                    if repo_info is not None:
                        if self.opts['namesonly'] and item['name'] != username:
                            continue
                        if eventName == "USERNAME" and "/" + username + "/" not in item.get('html_url', ''):
                            continue

                        evt = GhostOsintEvent("PUBLIC_CODE_REPO", repo_info,
                                              self.__name__, event)
                        self.notifyListeners(evt)


# End of GO_github class
