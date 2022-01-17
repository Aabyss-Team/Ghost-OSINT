# -------------------------------------------------------------------------------
# Name:        GO_fullcontact
# Purpose:     Gather domain and e-mail information from FullContact.com API.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/02/2018
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
from datetime import datetime

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_fullcontact(GhostOsintPlugin):

    meta = {
        'name': "FullContact",
        'summary': "通过 FullContact.com API 收集域名和电子邮件信息.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.fullcontact.com",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://dashboard.fullcontact.com/api-ref",
                "https://www.fullcontact.com/developer-portal/",
                "https://www.fullcontact.com/insights-bundles/",
                "https://dashboard.fullcontact.com/docs",
                "https://www.fullcontact.com/faq/"
            ],
            'apiKeyInstructions': [
                "访问 https://fullcontact.com",
                "注册一个免费账户",
                "导航到 https://dashboard.fullcontact.com",
                "点击 'Get an API Key'",
                "使用你的联系号码验证您的帐户",
                "API 密钥将在 'Your API Keys'"
            ],
            'favIcon': "https://1a3asl4eps7u26kl661u3bi9-wpengine.netdna-ssl.com/wp-content/uploads/2019/11/cropped-full-contact-isologo-32x32.png",
            'logo': "https://1a3asl4eps7u26kl661u3bi9-wpengine.netdna-ssl.com/wp-content/themes/fc-theme/assets/images/common/full-contact-logo.svg?1574450351",
            'description': "连接数据.巩固身份.应用见解.扩大媒体覆盖范围. "
            "我们提供以个人为中心的身份解析，通过简单、实时的API集成来改善客户交互.\n"
            "FullContact 是一家隐私安全的身份解析公司，旨在建立人与品牌之间的信任. "
            "我们通过统一数据并在关键时刻应用见解，提供创造定制客户体验所需的能力.",
        }
    }

    opts = {
        "api_key": "",
        "max_age_days": "365"
    }

    optdescs = {
        "api_key": "FullContact.com API 密钥.",
        "max_age_days": "记录在被视为无效且未报告之前的最大存在天数(以天为单位)."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "EMAILADDR"]

    def producedEvents(self):
        return [
            "EMAILADDR",
            "EMAILADDR_GENERIC",
            "RAW_RIR_DATA",
            "PHONE_NUMBER",
            "GEOINFO",
            "PHYSICAL_ADDRESS"
        ]

    def query(self, url, data, failcount=0):
        headers = {
            'Authorization': f"Bearer {self.opts['api_key']}"
        }

        res = self.GhostOsint.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent="GhostOSINT",
            postData=json.dumps(data),
            headers=headers
        )

        if res['code'] in ["401", "400"]:
            self.error("API key rejected by FullContact")
            self.errorState = True
            return None

        if res['code'] == "403":
            if failcount == 3:
                self.error("Throttled or other blocking by FullContact")
                return None

            time.sleep(2)
            failcount += 1
            return self.query(url, data, failcount)

        if not res['content']:
            self.error("No content returned from FullContact")
            return None

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from FullContact: {e}")
            return None

        if "updated" in ret and int(self.opts['max_age_days']) > 0:
            last_dt = datetime.strptime(ret['updated'], '%Y-%m-%d')
            last_ts = int(time.mktime(last_dt.timetuple()))
            age_limit_ts = int(time.time()) - (86400 * int(self.opts['max_age_days']))

            if last_ts < age_limit_ts:
                self.debug("FullContact record found but too old.")
                return None

        return ret

    def queryCompany(self, domain):
        url = "https://api.fullcontact.com/v3/company.enrich"

        if not domain:
            return None

        return self.query(url, {"domain": domain})

    def queryPersonByEmail(self, email):
        url = "https://api.fullcontact.com/v3/person.enrich"

        if not email:
            return None

        return self.query(url, {'email': email})

    def queryPersonByName(self, name):
        url = "https://api.fullcontact.com/v3/person.enrich"

        if not name:
            return None

        return self.query(url, {'fullName': name})

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "EMAILADDR":
            data = self.queryPersonByEmail(eventData)

            if not data:
                return

            full_name = data.get('fullName')

            if full_name:
                e = GhostOsintEvent("RAW_RIR_DATA", f"Possible full name: {full_name}", self.__name__, event)
                self.notifyListeners(e)

            return

        if eventName == "DOMAIN_NAME":
            data = self.queryCompany(eventData)

            if not data:
                return

            if data.get("details"):
                data = data['details']

            if data.get("emails"):
                for r in data['emails']:
                    email = r.get('value')

                    if not email:
                        continue

                    if email.split("@")[0] in self.opts['_genericusers'].split(","):
                        evttype = "EMAILADDR_GENERIC"
                    else:
                        evttype = "EMAILADDR"

                    e = GhostOsintEvent(evttype, email, self.__name__, event)
                    self.notifyListeners(e)

            if data.get("phones"):
                for r in data['phones']:
                    phone = r.get('value')

                    if not phone:
                        continue

                    e = GhostOsintEvent("PHONE_NUMBER", phone, self.__name__, event)
                    self.notifyListeners(e)

            if data.get("locations"):
                for r in data['locations']:
                    location = ', '.join([_f for _f in [r.get('city'), r.get('country')] if _f])
                    if location:
                        e = GhostOsintEvent(
                            "GEOINFO",
                            location,
                            self.__name__,
                            event
                        )
                        self.notifyListeners(e)

                    if r.get("formatted"):
                        # Seems to contain some junk sometimes
                        if len(r['formatted']) > 10:
                            e = GhostOsintEvent(
                                "PHYSICAL_ADDRESS",
                                r['formatted'],
                                self.__name__,
                                event
                            )
                            self.notifyListeners(e)

            if data.get("keyPeople"):
                for r in data['keyPeople']:
                    full_name = r.get('fullName')
                    if full_name:
                        e = GhostOsintEvent(
                            "RAW_RIR_DATA",
                            f"Possible full name: {full_name}",
                            self.__name__,
                            event
                        )
                        self.notifyListeners(e)

# End of GO_fullcontact class
