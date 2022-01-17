# -------------------------------------------------------------------------------
# Name:         GO_clearbit
# Purpose:      Query clearbit.com using their API.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/03/2017
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import base64
import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_clearbit(GhostOsintPlugin):

    meta = {
        'name': "Clearbit",
        'summary': "根据 clearbit.com 上的电子邮件地址来检查姓名、地址和域名等信息.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://clearbit.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://clearbit.com/docs"
            ],
            'apiKeyInstructions': [
                "访问 https://clearbit.com",
                "注册账户以获得免费使用",
                "导航到 https://dashboard.clearbit.com/api",
                "API 密钥将在 'Your API Key'"
            ],
            'favIcon': "https://clearbit.com/assets/site/logo.png",
            'logo': "https://clearbit.com/assets/site/logo.png",
            'description': "Clearbit 是所有客户交互的营销数据引擎. "
            "深入了解您的客户，确定未来前景，并个性化每一次营销和互动营销.\n"
            "通过我们专有的实时查找，依靠新鲜、准确的数据. "
            "然后立即对新信息采取行动，并发出销售警报和工作变更通知.\n"
            "获取公司属性，如员工数量、使用的技术和行业分类，并随时获取员工详细信息，如角色、资历，甚至工作变动通知.\n"
            "利用我们的数据集和机器学习算法，您将拥有转换潜在客户和发展业务所需的所有信息.",
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "api_key": "Clearbit.com API 密钥."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["EMAILADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["RAW_RIR_DATA", "PHONE_NUMBER", "PHYSICAL_ADDRESS",
                "AFFILIATE_INTERNET_NAME", "EMAILADDR", "EMAILADDR_GENERIC"]

    def query(self, t):
        api_key = self.opts['api_key']
        if type(api_key) == str:
            api_key = api_key.encode('utf-8')
        url = "https://person.clearbit.com/v2/combined/find?email=" + t
        token = base64.b64encode(api_key + ':'.encode('utf-8'))
        headers = {
            'Accept': 'application/json',
            'Authorization': "Basic " + token.decode('utf-8')
        }

        res = self.GhostOsint.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent="GhostOSINT", headers=headers)

        if res['code'] != "200":
            self.error("Return code indicates no results or potential API key failure or exceeded limits.")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from clearbit.io: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled GO_clearbit but did not set an API key!")
            self.errorState = True
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)
        if not data:
            return

        try:
            # Get the name associated with the e-mail
            if "person" in data:
                name = data['person']['name']['fullName']
                evt = GhostOsintEvent("RAW_RIR_DATA", "Possible full name: " + name,
                                      self.__name__, event)
                self.notifyListeners(evt)
        except Exception:
            self.debug("Unable to extract name from JSON.")
            pass

        # Get the location of the person, also indicating
        # the location of the employer.
        try:
            if "geo" in data:
                loc = ""

                if 'streetNumber' in data['geo']:
                    loc += data['geo']['streetNumber'] + ", "
                if 'streetName' in data['geo']:
                    loc += data['geo']['streetName'] + ", "
                if 'city' in data['geo']:
                    loc += data['geo']['city'] + ", "
                if 'postalCode' in data['geo']:
                    loc += data['geo']['postalCode'] + ", "
                if 'state' in data['geo']:
                    loc += data['geo']['state'] + ", "
                if 'country' in data['geo']:
                    loc += data['geo']['country']
                evt = GhostOsintEvent("PHYSICAL_ADDRESS", loc, self.__name__, event)
                self.notifyListeners(evt)
        except Exception:
            self.debug("Unable to extract location from JSON.")
            pass

        try:
            if "company" in data:
                if 'domainAliases' in data['company']:
                    for d in data['company']['domainAliases']:
                        evt = GhostOsintEvent("AFFILIATE_INTERNET_NAME", d,
                                              self.__name__, event)
                        self.notifyListeners(evt)

                if 'site' in data['company']:
                    if 'phoneNumbers' in data['company']['site']:
                        for p in data['company']['site']['phoneNumbers']:
                            evt = GhostOsintEvent("PHONE_NUMBER", p, self.__name__, event)
                            self.notifyListeners(evt)
                    if 'emailAddresses' in data['company']['site']:
                        for e in data['company']['site']['emailAddresses']:
                            if e.split("@")[0] in self.opts['_genericusers'].split(","):
                                evttype = "EMAILADDR_GENERIC"
                            else:
                                evttype = "EMAILADDR"
                            evt = GhostOsintEvent(evttype, e, self.__name__, event)
                            self.notifyListeners(evt)

                # Get the location of the person, also indicating
                # the location of the employer.
                if 'geo' in data['company']:
                    loc = ""

                    if 'streetNumber' in data['company']['geo']:
                        loc += data['company']['geo']['streetNumber'] + ", "
                    if 'streetName' in data['company']['geo']:
                        loc += data['company']['geo']['streetName'] + ", "
                    if 'city' in data['company']['geo']:
                        loc += data['company']['geo']['city'] + ", "
                    if 'postalCode' in data['company']['geo']:
                        loc += data['company']['geo']['postalCode'] + ", "
                    if 'state' in data['company']['geo']:
                        loc += data['company']['geo']['state'] + ", "
                    if 'country' in data['company']['geo']:
                        loc += data['company']['geo']['country']
                    evt = GhostOsintEvent("PHYSICAL_ADDRESS", loc, self.__name__, event)
                    self.notifyListeners(evt)
        except Exception:
            self.debug("Unable to company info from JSON.")
            pass

# End of GO_clearbit class
