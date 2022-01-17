# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_c99
# Purpose:      GhostOSINT plug-in that queries c99 API
#
# Author:      Filip Aleksić <faleksicdev@gmail.com>
#
# Created:     2020-08-27
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_c99(GhostOsintPlugin):
    meta = {
        "name": "C99",
        "summary": "通过 C99 的 API 查询各种数据 (地理位置、代理检测、电话查询等).",
        'flags': ["apikey"],
        "useCases": ["Footprint", "Passive", "Investigate"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://api.c99.nl/",
            "model": "COMMERCIAL_ONLY",
            "references": ["https://api.c99.nl/api_overview", "https://api.c99.nl/faq"],
            "apiKeyInstructions": [
                "访问 https://api.c99.nl",
                "点击顶部导航栏中的 'shop' 或访问  https://api.c99.nl/dashboard/shop",
                "点击选项中的购买 'C99.NL API KEY' (也可以购买一年的 API 密钥)",
                "你将通过电子邮件收到您的API密钥.",
            ],
            "favIcon": "https://api.c99.nl/favicon.ico",
            "logo": "https://api.c99.nl/assets/images/logo.png",
            "description": "C99 API 服务是多功能的信息源. "
            "他们提供超过57个不同的API，其中10个集成在此模块中. "
            "集成的API包括子域名查找、电话查找、Skype解析器、Skype IP地址、防火墙技术和WAF检测、域名历史记录、域名IP地址、IP地址地理位置、代理检测.",
        },
    }

    opts = {
        "api_key": "",
        "verify": True,
        "cohostsamedomain": False,
        "maxcohost": 100,
    }

    optdescs = {
        "api_key": "C99 API 密钥.",
        "verify": "验证标识域是否仍解析为关联的指定IP地址.",
        "maxcohost": "在发现这么多网站后，停止报告共同托管的网站，因为这可能表明网站是托管的.",
        "cohostsamedomain": "将同一目标域上的托管站点视为共同托管的?",
    }

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "PHONE_NUMBER",
            "IP_ADDRESS",
            "USERNAME",
            "EMAILADDR",
        ]

    def producedEvents(self):
        return [
            "RAW_RIR_DATA",
            "GEOINFO",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "PROVIDER_TELCO",
            "PHYSICAL_ADDRESS",
            "PHYSICAL_COORDINATES",
            "PROVIDER_DNS",
            "IP_ADDRESS",
            "USERNAME",
            "ACCOUNT_EXTERNAL_OWNED",
            "WEBSERVER_TECHNOLOGY",
            "PROVIDER_HOSTING",
            "CO_HOSTED_SITE"
        ]

    def query(self, path, queryParam, queryData):
        res = self.GhostOsint.fetchUrl(
            f"https://api.c99.nl/{path}?key={self.opts['api_key']}&{queryParam}={queryData}&json",
            timeout=self.opts["_fetchtimeout"],
            useragent="GhostOSINT",
        )

        if res["code"] == "429":
            self.error("Reaching rate limit on C99 API")
            self.errorState = True
            return None

        if res["code"] == 400:
            self.error("Invalid request or API key on C99 API")
            self.errorState = True
            return None

        if res["content"] is None:
            self.info(f"No C99 info found for {queryData}")
            return None

        try:
            info = json.loads(res["content"])
        except Exception as e:
            self.errorState = True
            self.error(f"Error processing response from C99: {e}")
            return None

        if not info.get('success', False):
            return None

        return info

    def emitRawRirData(self, data, event):
        evt = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

    def emitPhoneData(self, phoneData, event):
        provider = phoneData.get("provider")
        carrier = phoneData.get("carrier")
        city = phoneData.get("city")
        countryName = phoneData.get("country_name")
        region = phoneData.get("region")
        found = False

        if provider or carrier:
            evt = GhostOsintEvent(
                "PROVIDER_TELCO",
                f"Provider: {provider}, Carrier: {carrier}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)
            found = True

        if city or countryName or region:
            evt = GhostOsintEvent(
                "PHYSICAL_ADDRESS",
                f"Country: {countryName}, Region: {region}, City: {city}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)
            found = True

        if found:
            self.emitRawRirData(phoneData, event)

    def emitSubDomainData(self, subDomainData, event):
        found = False

        for subDomainElem in subDomainData:
            if self.checkForStop():
                return

            subDomain = subDomainElem.get("subdomain", "").strip()

            if subDomain:
                self.emitHostname(subDomain, event)
                found = True

        if found:
            self.emitRawRirData(subDomainData, event)

    def emitDomainHistoryData(self, domainHistoryData, event):
        found = False

        for domainHistoryElem in domainHistoryData:
            if self.checkForStop():
                return

            ip = domainHistoryElem.get("ip_address")

            if self.GhostOsint.validIP(ip):
                evt = GhostOsintEvent(
                    "IP_ADDRESS",
                    ip,
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)
                found = True

        if found:
            self.emitRawRirData(domainHistoryData, event)

    def emitIpToSkypeData(self, data, event):
        skype = data.get("skype")

        if skype:
            evt = GhostOsintEvent(
                "ACCOUNT_EXTERNAL_OWNED",
                f"Skype [{skype}]",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

            evt = GhostOsintEvent(
                "USERNAME",
                skype,
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

            self.emitRawRirData(data, event)

    def emitIpToDomainsData(self, data, event):
        domains = data.get("domains")
        found = False

        if isinstance(domains, list):
            for domain in domains:
                if self.checkForStop():
                    return

                domain = domain.strip()
                if domain:
                    self.emitHostname(domain, event)
                    found = True

        if found:
            self.emitRawRirData(data, event)

    def emitProxyDetectionData(self, data, event):
        isProxy = data.get("proxy")

        if isProxy:
            evt = GhostOsintEvent(
                "WEBSERVER_TECHNOLOGY",
                f"Server is proxy: {isProxy}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)
            self.emitRawRirData(data, event)

    def emitGeoIPData(self, data, event):
        found = False

        hostName = data.get("hostname", "").strip()
        if hostName:
            self.emitHostname(hostName, event)
            found = True

        record = data.get("records")

        if record:
            country = record.get("country_name")
            region = record["region"].get("name") if record.get("region") else None
            city = record.get("city")
            postalCode = record.get("postal_code")
            latitude = record.get("latitude")
            longitude = record.get("longitude")
            provider = record.get("isp")

            if provider:
                evt = GhostOsintEvent(
                    "PROVIDER_HOSTING",
                    provider,
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)
                found = True

            if latitude and longitude:
                evt = GhostOsintEvent(
                    "PHYSICAL_COORDINATES",
                    f"{latitude}, {longitude}",
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)
                found = True

            if region or country or city or postalCode:
                evt = GhostOsintEvent(
                    "GEOINFO",
                    f"Country: {country}, Region: {region}, City: {city}, Postal code: {postalCode}",
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)
                found = True

        if found:
            self.emitRawRirData(data, event)

    def emitSkypeResolverData(self, data, event):
        ip = data.get("ip")
        ips = data.get("ips")
        found = False

        if ip and ip not in ips:
            evt = GhostOsintEvent(
                "IP_ADDRESS",
                ip,
                self.__name__,
                event,
            )
            self.notifyListeners(evt)
            found = True

        if isinstance(ips, list):
            found = True
            for ipElem in ips:
                if self.checkForStop():
                    return

                evt = GhostOsintEvent(
                    "IP_ADDRESS",
                    ipElem.strip(),
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

        if found:
            self.emitRawRirData(data, event)

    def emitWafDetectorData(self, data, event):
        firewall = data.get("result")

        if firewall:
            evt = GhostOsintEvent(
                "WEBSERVER_TECHNOLOGY",
                f"Firewall detected: {firewall}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)
            self.emitRawRirData(data, event)

    def emitHostname(self, data, event):
        if not self.GhostOsint.validHost(data, self.opts['_internettlds']):
            return

        if self.opts["verify"] and not self.GhostOsint.resolveHost(data) and not self.GhostOsint.resolveHost6(data):
            self.debug(f"Host {data} could not be resolved.")
            if self.getTarget().matches(data):
                evt = GhostOsintEvent("INTERNET_NAME_UNRESOLVED", data, self.__name__, event)
                self.notifyListeners(evt)
            return

        if self.getTarget().matches(data):
            evt = GhostOsintEvent('INTERNET_NAME', data, self.__name__, event)
            self.notifyListeners(evt)
            if self.GhostOsint.isDomain(data, self.opts['_internettlds']):
                evt = GhostOsintEvent('DOMAIN_NAME', data, self.__name__, event)
                self.notifyListeners(evt)
            return

        if self.cohostcount < self.opts['maxcohost']:
            if self.opts["verify"] and not self.GhostOsint.validateIP(data, event.data):
                self.debug("Host no longer resolves to our IP.")
                return

            if not self.opts["cohostsamedomain"]:
                if self.getTarget().matches(data, includeParents=True):
                    self.debug(
                        f"Skipping {data} because it is on the same domain."
                    )
                    return

            if self.cohostcount < self.opts["maxcohost"]:
                evt = GhostOsintEvent("CO_HOSTED_SITE", data, self.__name__, event)
                self.notifyListeners(evt)
                self.cohostcount += 1

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # Once we are in this state, return immediately.
        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error("You enabled GO_c99, but did not set an API key!")
            self.errorState = True
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "PHONE_NUMBER":
            phoneData = self.query("phonelookup", "number", eventData)
            phoneData = phoneData.get("details") if phoneData else None

            if phoneData:
                self.emitPhoneData(phoneData, event)

        if eventName == "DOMAIN_NAME":
            subDomainData = self.query("subdomainfinder", "domain", eventData)
            subDomainData = (
                subDomainData.get("subdomains") if subDomainData is not None else None
            )

            if isinstance(subDomainData, list):
                self.emitSubDomainData(subDomainData, event)

            domainHistoryData = self.query("domainhistory", "domain", eventData)
            domainHistoryData = (
                domainHistoryData.get("result") if domainHistoryData else None
            )

            if isinstance(domainHistoryData, list):
                self.emitDomainHistoryData(domainHistoryData, event)

            wafDetectorData = self.query("firewalldetector", "url", eventData)

            if wafDetectorData:
                self.emitWafDetectorData(wafDetectorData, event)

        if eventName == "IP_ADDRESS":
            ipToSkypeData = self.query("ip2skype", "ip", eventData)

            if ipToSkypeData:
                self.emitIpToSkypeData(ipToSkypeData, event)

            ipToDomainsData = self.query("ip2domains", "ip", eventData)

            if ipToDomainsData:
                self.emitIpToDomainsData(ipToDomainsData, event)

            proxyDetectionData = self.query("proxydetector", "ip", eventData)

            if proxyDetectionData:
                self.emitProxyDetectionData(proxyDetectionData, event)

            geoIPData = self.query("geoip", "host", eventData)

            if geoIPData:
                self.emitGeoIPData(geoIPData, event)

        if eventName == "USERNAME":
            skypeResolverData = self.query("skyperesolver", "username", eventData)

            if skypeResolverData:
                self.emitSkypeResolverData(skypeResolverData, event)


# End of GO_c99 class
