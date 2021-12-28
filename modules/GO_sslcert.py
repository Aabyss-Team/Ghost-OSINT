# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         GO_sslcert
# Purpose:      Gather information about SSL certificates behind HTTPS sites.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     23/08/2013
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from urllib.parse import urlparse

from ghostosint import GhostOsintEvent, GhostOsintPlugin


class GO_sslcert(GhostOsintPlugin):

    meta = {
        'name': "SSL Certificate Analyzer",
        'summary': "Gather information about SSL certificates used by the target's HTTPS sites.",
        'flags': [],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"]
    }

    # Default options
    opts = {
        "tryhttp": True,
        'verify': True,
        "ssltimeout": 10,
        "certexpiringdays": 30
    }

    # Option descriptions
    optdescs = {
        "tryhttp": "Also try to HTTPS-connect to HTTP sites and hostnames.",
        'verify': "Verify certificate subject alternative names resolve.",
        "ssltimeout": "Seconds before giving up trying to HTTPS connect.",
        "certexpiringdays": "Number of days in the future a certificate expires to consider it as expiring."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.GhostOsint = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "LINKED_URL_INTERNAL", "IP_ADDRESS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ['TCP_PORT_OPEN', 'INTERNET_NAME', 'INTERNET_NAME_UNRESOLVED',
                'AFFILIATE_INTERNET_NAME', 'AFFILIATE_INTERNET_NAME_UNRESOLVED',
                "SSL_CERTIFICATE_ISSUED", "SSL_CERTIFICATE_ISSUER",
                "SSL_CERTIFICATE_MISMATCH", "SSL_CERTIFICATE_EXPIRED",
                "SSL_CERTIFICATE_EXPIRING", "SSL_CERTIFICATE_RAW",
                "DOMAIN_NAME", 'AFFILIATE_DOMAIN_NAME']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName == "LINKED_URL_INTERNAL":
            if not eventData.lower().startswith("https://") and not self.opts['tryhttp']:
                return

            try:
                # Handle URLs containing port numbers
                u = urlparse(eventData)
                port = 443
                if u.port:
                    port = u.port
                fqdn = self.GhostOsint.urlFQDN(eventData.lower())
            except Exception:
                self.debug("Couldn't parse URL: " + eventData)
                return
        else:
            fqdn = eventData
            port = 443

        if fqdn not in self.results:
            self.results[fqdn] = True
        else:
            return

        self.debug("Testing SSL for: " + fqdn + ':' + str(port))
        # Re-fetch the certificate from the site and process
        try:
            sock = self.GhostOsint.safeSSLSocket(fqdn, port, self.opts['ssltimeout'])
            sock.do_handshake()
            dercert = sock.getpeercert(True)
            pemcert = self.GhostOsint.sslDerToPem(dercert)
            cert = self.GhostOsint.parseCert(str(pemcert), fqdn, self.opts['certexpiringdays'])
        except Exception as x:
            self.info("Unable to SSL-connect to " + fqdn + " (" + str(x) + ")")
            return

        if eventName in ['INTERNET_NAME', 'IP_ADDRESS']:
            evt = GhostOsintEvent('TCP_PORT_OPEN', fqdn + ':' + str(port), self.__name__, event)
            self.notifyListeners(evt)

        if not cert.get('text'):
            self.info("Failed to parse the SSL cert for " + fqdn)
            return

        # Generate the event for the raw cert (in text form)
        # Cert raw data text contains a lot of gems..
        rawevt = GhostOsintEvent("SSL_CERTIFICATE_RAW", cert['text'], self.__name__, event)
        self.notifyListeners(rawevt)

        if cert.get('issued'):
            evt = GhostOsintEvent('SSL_CERTIFICATE_ISSUED', cert['issued'], self.__name__, event)
            self.notifyListeners(evt)

        if cert.get('issuer'):
            evt = GhostOsintEvent('SSL_CERTIFICATE_ISSUER', cert['issuer'], self.__name__, event)
            self.notifyListeners(evt)

        if eventName != "IP_ADDRESS" and cert.get('mismatch'):
            evt = GhostOsintEvent('SSL_CERTIFICATE_MISMATCH', ', '.join(cert.get('hosts')), self.__name__, event)
            self.notifyListeners(evt)

        for san in set(cert.get('altnames', list())):
            domain = san.replace("*.", "")

            if self.getTarget().matches(domain, includeChildren=True):
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

        if cert.get('expired'):
            evt = GhostOsintEvent("SSL_CERTIFICATE_EXPIRED", cert.get('expirystr', 'Unknown'), self.__name__, event)
            self.notifyListeners(evt)
            return

        if cert.get('expiring'):
            evt = GhostOsintEvent("SSL_CERTIFICATE_EXPIRING", cert.get('expirystr', 'Unknown'), self.__name__, event)
            self.notifyListeners(evt)

# End of GO_sslcert class
