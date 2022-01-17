# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_opencorporates
# Purpose:      GhostOSINT plug-in for retrieving company information from
#               OpenCorporates.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-21
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_opencorporates(GhostOsintPlugin):

    meta = {
        'name': "OpenCorporates",
        'summary': "从 OpenCorporates 查找公司信息.",
        'flags': ["apikey"],
        'useCases': ["Passive", "Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://opencorporates.com",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://api.opencorporates.com/documentation/API-Reference"
            ],
            'apiKeyInstructions': [
                "访问 https://opencorporates.com/api_accounts/new"
                "使用电子邮件注册一个账户",
                "导航到 https://opencorporates.com/users/account and select 'Get Account'",
                "选择计划",
                "导航到 https://opencorporates.com/users/account",
                "API 密钥将在 'API Account'",
            ],
            'favIcon': "https://opencorporates.com/assets/favicons/favicon.png",
            'logo': "https://opencorporates.com/contents/ui/theme/img/oc-logo.svg",
            'description': "世界上最大的公司开放数据库.\n"
            "作为世界上最大的开放式公司数据库，我们的业务是公开提供高质量的官方公司数据. "
            "在需要时以及以何种方式可以信任、访问、分析和查询的数据.",
        }
    }

    opts = {
        'confidence': 100,
        'api_key': ''
    }

    optdescs = {
        'confidence': "确信搜索结果对象是正确的（数值介于0和100之间）.",
        'api_key': 'OpenCorporates.com API 密钥. 否则，你每天只能进行50次查询.'
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["COMPANY_NAME"]

    def producedEvents(self):
        return ["COMPANY_NAME", "PHYSICAL_ADDRESS", "RAW_RIR_DATA"]

    def searchCompany(self, qry):
        """Search for company name

        Args:
            qry (str): company name

        Returns:
            str
        """

        version = '0.4'

        apiparam = ""
        if self.opts['api_key']:
            apiparam = "&api_token=" + self.opts['api_key']

        params = urllib.parse.urlencode({
            'q': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'format': 'json',
            'order': 'score',
            'confidence': self.opts['confidence']
        })

        res = self.GhostOsint.fetchUrl(
            f"https://api.opencorporates.com/v{version}/companies/search?{params}{apiparam}",
            timeout=60,  # High timeouts as they can sometimes take a while
            useragent=self.opts['_useragent']
        )

        if res['code'] == "401":
            self.error("Invalid OpenCorporates API key.")
            return None

        if res['code'] == "403":
            self.error("You are being rate-limited by OpenCorporates.")
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        if 'results' not in data:
            return None

        return data['results']

    def retrieveCompanyDetails(self, jurisdiction_code, company_number):
        url = f"https://api.opencorporates.com/companies/{jurisdiction_code}/{company_number}"

        if self.opts['api_key']:
            url += "?api_token=" + self.opts['api_key']

        res = self.GhostOsint.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent']
        )

        if res['code'] == "401":
            self.error("Invalid OpenCorporates API key.")
            return None

        if res['code'] == "403":
            self.error("You are being rate-limited by OpenCorporates.")
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        if 'results' not in data:
            return None

        return data['results']

    # Extract company address, previous names, and officer names
    def extractCompanyDetails(self, company, sevt):

        # Extract registered address
        location = company.get('registered_address_in_full')

        if location:
            if len(location) < 3 or len(location) > 100:
                self.debug("Skipping likely invalid location.")
            else:
                if company.get('registered_address'):
                    country = company.get('registered_address').get('country')
                    if country:
                        if not location.endswith(country):
                            location += ", " + country

                location = location.replace("\n", ',')
                self.info("Found company address: " + location)
                e = GhostOsintEvent("PHYSICAL_ADDRESS", location, self.__name__, sevt)
                self.notifyListeners(e)

        # Extract previous company names
        previous_names = company.get('previous_names')

        if previous_names:
            for previous_name in previous_names:
                p = previous_name.get('company_name')
                if p:
                    self.info("Found previous company name: " + p)
                    e = GhostOsintEvent("COMPANY_NAME", p, self.__name__, sevt)
                    self.notifyListeners(e)

        # Extract officer names
        officers = company.get('officers')

        if officers:
            for officer in officers:
                n = officer.get('name')
                if n:
                    self.info("Found company officer: " + n)
                    e = GhostOsintEvent("RAW_RIR_DATA", "Possible full name: " + n, self.__name__, sevt)
                    self.notifyListeners(e)

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == '':
            self.error(f"Warning: You enabled {self.__class__.__name__} but did not set an API key! Queries will be limited to 50 per day and 200 per month.")

        res = self.searchCompany(f"{eventData}*")

        if res is None:
            self.debug("Found no results for " + eventData)
            return

        companies = res.get('companies')

        if not companies:
            self.debug("Found no results for " + eventData)
            return

        for c in companies:
            company = c.get('company')

            if not company:
                continue

            # Check for match
            if eventData.lower() != company.get('name').lower():
                continue

            # Extract company details from search results
            self.extractCompanyDetails(company, event)

            # Retrieve further details
            jurisdiction_code = company.get('jurisdiction_code')
            company_number = company.get('company_number')

            if not company_number or not jurisdiction_code:
                continue

            res = self.retrieveCompanyDetails(jurisdiction_code, company_number)

            if not res:
                continue

            c = res.get('company')

            if not c:
                continue

            self.extractCompanyDetails(c, event)

# End of GO_opencorporates class
