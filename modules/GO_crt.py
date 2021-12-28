# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_crt
# Purpose:      GhostOSINT plug-in to identify historical certificates for a domain
#               from crt.sh, and from this identify hostnames.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     17/03/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib.parse

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_crt(GhostOsintPlugin):

    meta = {
        'name': "Certificate Transparency",
        'summary': "Gather hostnames from historical certificates in crt.sh.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://crt.sh/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://sectigo.com/",
                "https://github.com/crtsh"
            ],
            'favIcon': "https://crt.sh/sectigo_s.png",
            'logo': "https://crt.sh/sectigo_s.png",
            'description': "Enter an Identity (Domain Name, Organization Name, etc), "
            "a Certificate Fingerprint (SHA-1 or SHA-256) or a crt.sh ID",
        }
    }

    opts = {
        'verify': True,
        'fetchcerts': True,
    }

    optdescs = {
        'verify': 'Verify certificate subject alternative names resolve.',
        'fetchcerts': 'Fetch each certificate found, for processing by other modules.',
    }

    results = None
    cert_ids = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()
        self.cert_ids = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['DOMAIN_NAME', 'INTERNET_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SSL_CERTIFICATE_RAW", "RAW_RIR_DATA",
                'INTERNET_NAME', 'INTERNET_NAME_UNRESOLVED', 'DOMAIN_NAME',
                'AFFILIATE_INTERNET_NAME', 'AFFILIATE_INTERNET_NAME_UNRESOLVED',
                'AFFILIATE_DOMAIN_NAME']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        params = {
            'q': '%.' + eventData.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'output': 'json'
        }

        res = self.GhostOsint.fetchUrl('https://crt.sh/?' + urllib.parse.urlencode(params),
                               timeout=30,
                               useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.info("No certificate transparency info found for " + eventData)
            return

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return

        if data is None or len(data) == 0:
            return

        evt = GhostOsintEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

        domains = list()
        fetch_certs = list()

        for cert_info in data:
            cert_id = cert_info.get('id')

            if cert_id:
                # Don't process the same cert twice
                if cert_id in self.cert_ids:
                    continue
                self.cert_ids[cert_id] = True

            if self.opts['fetchcerts']:
                fetch_certs.append(cert_id)

            domain = cert_info.get('name_value')

            if not domain:
                continue

            for d in domain.split("\n"):
                if d.lower() == eventData.lower():
                    continue
                domains.append(d.lower().replace("*.", ""))

        if self.opts['verify'] and len(domains) > 0:
            self.info(f"Resolving {len(set(domains))} domains ...")

        for domain in set(domains):
            if domain in self.results:
                continue

            if not self.GhostOsint.validHost(domain, self.opts['_internettlds']):
                continue

            if self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                evt_type = 'INTERNET_NAME'
            else:
                evt_type = 'AFFILIATE_INTERNET_NAME'

            if self.opts['verify'] and not self.GhostOsint.resolveHost(domain) and not self.GhostOsint.resolveHost6(domain):
                self.debug(f"Host {domain} could not be resolved")
                evt_type += '_UNRESOLVED'

            evt = GhostOsintEvent(evt_type, domain, self.__name__, event)
            self.notifyListeners(evt)

            if self.GhostOsint.isDomain(domain, self.opts['_internettlds']):
                if evt_type.startswith('AFFILIATE'):
                    evt = GhostOsintEvent('AFFILIATE_DOMAIN_NAME', domain, self.__name__, event)
                    self.notifyListeners(evt)
                else:
                    evt = GhostOsintEvent('DOMAIN_NAME', domain, self.__name__, event)
                    self.notifyListeners(evt)

        for cert_id in fetch_certs:
            if self.checkForStop():
                return

            params = {
                'd': str(cert_id)
            }

            res = self.GhostOsint.fetchUrl('https://crt.sh/?' + urllib.parse.urlencode(params),
                                   timeout=30,
                                   useragent=self.opts['_useragent'])

            if res['content'] is None:
                self.info("Error retrieving certificate with ID " + str(cert_id))
                continue

            try:
                cert = self.GhostOsint.parseCert(str(res['content']))
            except Exception as e:
                self.info('Error parsing certificate: ' + str(e))
                continue

            evt = GhostOsintEvent("SSL_CERTIFICATE_RAW", cert['text'], self.__name__, event)
            self.notifyListeners(evt)

# End of GO_crt class
