# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        GO_webanalytics
# Purpose:     Scans retrieved content by other modules (such as GO_spider and
#              GO_dnsraw) and retrieves web analytics and tracking IDs.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-28
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_webanalytics(GhostOsintPlugin):

    meta = {
        'name': "Web Analytics Extractor",
        'summary': "Identify web analytics IDs in scraped webpages and DNS TXT records.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    opts = {}
    optdescs = {}

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['TARGET_WEB_CONTENT', 'DNS_TEXT']

    # What events this module produces
    def producedEvents(self):
        return ["WEB_ANALYTICS_ID"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        sourceData = self.GhostOsint.hashstring(eventData)

        if sourceData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[sourceData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if event.moduleDataSource:
            datasource = event.moduleDataSource
        else:
            datasource = "Unknown"

        if eventName == 'TARGET_WEB_CONTENT':
            # Google Analytics
            matches = re.findall(r"\bua\-\d{4,10}\-\d{1,4}\b", eventData, re.IGNORECASE)
            for m in matches:
                if m.lower().startswith('ua-000000-'):
                    continue
                if m.lower().startswith('ua-123456-'):
                    continue
                if m.lower().startswith('ua-12345678'):
                    continue

                self.debug("Google Analytics match: " + m)
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Google Analytics: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Google AdSense
            matches = re.findall(r"\b(pub-\d{10,20})\b", eventData, re.IGNORECASE)
            for m in matches:
                if m.lower().startswith('pub-12345678'):
                    continue

                self.debug("Google AdSense match: " + m)
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Google AdSense: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Google Website Verification
            # https://developers.google.com/site-verification/v1/getting_started
            matches = re.findall(r'<meta name="google-site-verification" content="([a-z0-9\-\+_=]{43,44})"', eventData, re.IGNORECASE)
            for m in matches:
                self.debug("Google Site Verification match: " + m)
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Google Site Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            matches = re.findall(r'<meta name="verify-v1" content="([a-z0-9\-\+_=]{43,44})"', eventData, re.IGNORECASE)
            for m in matches:
                self.debug("Google Site Verification match: " + m)
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Google Site Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Quantcast
            if '_qevents.push' in eventData:
                matches = re.findall(r"\bqacct:\"(p-[a-z0-9]+)\"", eventData, re.IGNORECASE)
                for m in matches:
                    self.debug("Quantcast match: " + m)
                    evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                          "Quantcast: " + m,
                                          self.__name__, event)
                    evt.moduleDataSource = datasource
                    self.notifyListeners(evt)

            # Ahrefs Site Verification
            matches = re.findall(r'<meta name="ahrefs-site-verification" content="([a-f0-9]{64})"', eventData, re.IGNORECASE)
            for m in matches:
                self.debug("Ahrefs Site Verification match: " + m)
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Ahrefs Site Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

        if eventName == 'DNS_TEXT':
            # Google Website Verification
            # https://developers.google.com/site-verification/v1/getting_started
            matches = re.findall(r'google-site-verification=([a-z0-9\-\+_=]{43,44})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Google Site Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # LogMeIn Domain Verification
            # https://support.logmeininc.com/openvoice/help/adding-a-txt-record-to-a-dns-server-ov710011
            matches = re.findall(r'logmein-domain-confirmation ([A-Z0-9]{24})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "LogMeIn Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            matches = re.findall(r'logmein-verification-code=([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "LogMeIn Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # DocuSign Domain Verification
            # https://support.docusign.com/en/guides/org-admin-guide-domains
            matches = re.findall(r'docusign=([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "DocuSign Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # GlobalSign Site Verification
            # https://support.globalsign.com/customer/en/portal/articles/2167245-performing-domain-verification---dns-txt-record
            matches = re.findall(r'globalsign-domain-verification=([a-z0-9\-\+_=]{42,44})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "GlobalSign Site Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Atlassian Domain Verification
            # https://confluence.atlassian.com/cloud/verify-a-domain-for-your-organization-873871234.html
            matches = re.findall(r'atlassian-domain-verification=([a-z0-9\-\+\/_=]{64})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Atlassian Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Adobe IDP Site Verification
            # https://helpx.adobe.com/au/enterprise/using/verify-domain-ownership.html
            matches = re.findall(r'adobe-idp-site-verification=([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Adobe IDP Site Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            matches = re.findall(r'adobe-idp-site-verification=([a-f0-9]{64})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Adobe IDP Site Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Adobe Domain Verification
            # https://helpx.adobe.com/sign/help/domain_claiming.html
            matches = re.findall(r'adobe-sign-verification=([a-f0-9]{32})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Adobe Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Stripe Domain Verification
            # https://stripe.com/docs/apple-pay/web#going-live
            matches = re.findall(r'stripe-verification=([a-f0-9]{64})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Stripe Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # TeamViewer SSO Verification
            # https://community.teamviewer.com/t5/Knowledge-Base/Single-Sign-On-SSO/ta-p/30784
            matches = re.findall(r'teamviewer-sso-verification=([a-f0-9]{32})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "TeamViewer SSO Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Aliyun Site Verification
            matches = re.findall(r'aliyun-site-verification=([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Aliyun Site Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Facebook Domain Verification
            # https://developers.facebook.com/docs/sharing/domain-verification/
            matches = re.findall(r'facebook-domain-verification=([a-z0-9]{30})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Facebook Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Citrix Domain Verification
            matches = re.findall(r'citrix-verification-code=([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Citrix Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Dropbox Domain Verification
            # https://help.dropbox.com/teams-admins/admin/domain-insights-account-capture#verify
            matches = re.findall(r'dropbox-domain-verification=([a-z0-9]{12})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Dropbox Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Detectify Domain Verification
            # https://support.detectify.com/customer/en/portal/articles/2836806-verification-with-dns-txt-
            matches = re.findall(r'detectify-verification=([a-f0-9]{32})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Detectify Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Drift Domain Verification
            matches = re.findall(r'drift-verification=([a-f0-9]{64})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Drift Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Ahrefs Site Verification
            # https://help.ahrefs.com/en/articles/1431155-how-do-i-finish-crawling-my-website-faster-in-site-audit
            matches = re.findall(r'ahrefs-site-verification_([a-f0-9]{64})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Ahrefs Site Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Statuspage.io Domain Verification
            # https://help.statuspage.io/help/domain-ownership
            matches = re.findall(r'status-page-domain-verification=([a-z0-9]{12})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Statuspage Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Zoom.us Domain Verification
            # https://support.zoom.us/hc/en-us/articles/203395207-What-is-Managed-Domain-
            matches = re.findall(r'ZOOM_verify_([a-z0-9\-\+\/_=]{22})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Zoom.us Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Mail.ru Domain Verification
            matches = re.findall(r'mailru-verification: ([a-z0-9]{16})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Mail.ru Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Yandex Domain Verification
            matches = re.findall(r'yandex-verification: ([a-z0-9]{16})$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Yandex Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Brave Ledger Verification
            # https://support.brave.com/hc/en-us/articles/360021408352-How-do-I-verify-my-channel-
            matches = re.findall(r'brave-ledger-verification=([a-z0-9]+)$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Brave Ledger Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # have-i-been-pwned Verification
            matches = re.findall(r'have-i-been-pwned-verification=([a-f0-9]+)$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "have-i-been-pwned Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

            # Cisco Live Domain Verification
            # https://www.ciscolive.com/c/dam/r/ciscolive/us/docs/2016/pdf/TECCOL-2982.pdf
            matches = re.findall(r'cisco-ci-domain-verification=([a-f0-9]+)$', eventData.strip(), re.IGNORECASE)
            for m in matches:
                evt = GhostOsintEvent("WEB_ANALYTICS_ID",
                                      "Cisco Live Domain Verification: " + m,
                                      self.__name__, event)
                evt.moduleDataSource = datasource
                self.notifyListeners(evt)

# End of GO_webanalytics class
