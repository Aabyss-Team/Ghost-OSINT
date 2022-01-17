# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_hostio
# Purpose:      Host.io database query module
#
# Author:      Lev Trubach <leotrubach@gmail.com>
#
# Created:     2020-08-21
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------
import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_hostio(GhostOsintPlugin):

    meta = {
        "name": "Host.io",
        "summary": "从 host.io 获取有关域名的信息.",
        'flags': ["apikey"],
        "useCases": ["Passive"],
        "categories": ["Passive DNS"],
        "dataSource": {
            "website": "https://host.io",
            "model": "FREE_AUTH_LIMITED",
            "references": ["https://host.io/docs"],
            "apiKeyInstructions": [
                "访问 https://host.io/signup",
                "注册一个免费账户",
                "访问 https://host.io/dashboard 并使用提供的身份验证令牌",
            ],
            "favIcon": "https://host.io/static/images/hostio/favicon.png?v2",
            "logo": "https://host.io/static/images/hostio/favicon.png?v2",  # Seems like they embed it as SVG
            "description": "我们从每个TLD收集每个已知域名的数据，并每月更新. "
            "我们的数据包括每个域的DNS记录和网站数据."
            "我们处理万亿字节的数据，并对其进行汇总以产生最终结果. "
            "浏览我们的网站，查看反向链接、重定向、服务器详细信息或IP地址和托管提供商详细信息，由 IPinfo.io 提供.",
        },
    }

    opts = {
        "api_key": "",
    }

    optdescs = {
        "api_key": "Host.io API 密钥.",
    }

    errorState = False

    def setup(self, sfc, userOpts=None):
        if userOpts is None:
            userOpts = {}
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.opts.update(userOpts)

    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "IP_ADDRESS",
            "RAW_RIR_DATA",
            "EMAILADDR",
            "WEB_ANALYTICS_ID",
            "WEBSERVER_TECHNOLOGY",
            "PHYSICAL_COORDINATES",
            "DESCRIPTION_ABSTRACT",
            "GEOINFO",
        ]

    # When querying third parties, it's best to have a dedicated function
    # to do so and avoid putting it in handleEvent()
    def handle_error_response(self, qry, res):
        try:
            error_info = json.loads(res["content"])
        except Exception:
            error_info = None
        if error_info:
            error_message = error_info.get("error")
        else:
            error_message = None
        if error_message:
            error_str = f", message {error_message}"
        else:
            error_str = ""
        self.info(f"Failed to get results for {qry}, code {res['code']}{error_str}")

    def query(self, qry):
        res = self.GhostOsint.fetchUrl(
            f"https://host.io/api/full/{qry}",
            headers={"Authorization": f"Bearer {self.opts['api_key']}"},
            timeout=self.opts["_fetchtimeout"],
            useragent="GhostOSINT",
        )
        if res["code"] != "200":
            self.handle_error_response(qry, res)
            return None

        if res["content"] is None:
            self.info(f"No Host.io info found for {qry}")
            return None

        try:
            return json.loads(res["content"])
        except Exception as e:
            self.error(f"Error processing JSON response from Host.io: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already mapped.")
            return

        self.results[eventData] = True

        data = self.query(event.data)
        if not data:
            self.error(f"No data received for {event.data}")
            return

        found = False
        ipinfo = data.get("ipinfo")
        if ipinfo and isinstance(ipinfo, dict):
            for address, ip_data in data["ipinfo"].items():
                # Not supporting co-hosted sites yet
                if not self.GhostOsint.validIP(address):
                    continue
                evt = GhostOsintEvent("IP_ADDRESS", address, self.__name__, event)
                self.notifyListeners(evt)
                found = True

                loc = ip_data.get("loc")
                if loc and isinstance(loc, str):
                    loc_evt = GhostOsintEvent(
                        "PHYSICAL_COORDINATES", loc, self.__name__, evt
                    )
                    self.notifyListeners(loc_evt)
                    found = True

                geo_info = ', '.join(filter(None, (ip_data.get(k) for k in ("city", "region", "country"))))
                if geo_info:
                    geo_info_evt = GhostOsintEvent(
                        "GEOINFO", geo_info, self.__name__, evt
                    )
                    self.notifyListeners(geo_info_evt)
                    found = True

        related = data.get("related")
        if related and isinstance(related, dict):
            email_section = related.get("email")
            if email_section and isinstance(email_section, list):
                for email_data in email_section:
                    if isinstance(email_data, dict):
                        value = email_data["value"]
                        if value and isinstance(value, str):
                            evt = GhostOsintEvent(
                                "EMAILADDR", value, self.__name__, event
                            )
                            self.notifyListeners(evt)
                            found = True

        web = data.get("web")
        if web and isinstance(web, dict):
            server = web.get("server")
            if server and isinstance(server, str):
                evt = GhostOsintEvent(
                    "WEBSERVER_TECHNOLOGY", server, self.__name__, event
                )
                self.notifyListeners(evt)
                found = True

            google_analytics = web.get("googleanalytics")
            if google_analytics and isinstance(google_analytics, str):
                evt = GhostOsintEvent(
                    "WEB_ANALYTICS_ID", google_analytics, self.__name__, event
                )
                self.notifyListeners(evt)
                found = True

            title = web.get("title")
            if title and isinstance(title, str):
                evt = GhostOsintEvent(
                    "DESCRIPTION_ABSTRACT", title, self.__name__, event
                )
                self.notifyListeners(evt)
                found = True

        if found:
            evt = GhostOsintEvent(
                "RAW_RIR_DATA", json.dumps(data), self.__name__, event
            )
            self.notifyListeners(evt)
