# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from .constants import (
    SEVERITY_MAP,
    SEVERITIES,
    ARCHES,
    OrderedDict,
    filter_products,
)

class Vex(object):
    """
    Class to hold VEX object
    """

    def __init__(self, vexdata):
        self.raw = vexdata
        self.parse_vulns()

    def parse_vulns(self):
        """
        Parse base vulnerability characteristics
        :return:
        """

        for k in self.raw['vulnerabilities']:
            self.title          = k['title']
            self.cve            = k['cve']
            self.cwe_id         = k['cwe']['id']
            self.cwe_name       = k['cwe']['name']
            self.discovery_date = k['discovery_date']
            self.release_date   = k['release_date']

        # Acknowledgements
        self.acks = None
        for x in k['acknowledgments']:
            for a in x:
                if len(x[a]) == 1:
                    self.acks = x[a][0]
                # TODO: if there's 2, we can 'and' if there's more than 2 it should be '1, 2 and 3'
                elif len(x[a]) > 1:
                    self.acks = " and ".join(x[a])

        # Bugzilla / bugtracking
        for x in k['ids']:
            if x['system_name'] == 'Red Hat Bugzilla ID':
              self.bz_id = x['text']
              self.bz_url = f'https://bugzilla.redhat.com/show_bug.cgi?id={self.bz_id}'

        # Notes including descriptions, summaries, statements
        # TODO: oddly it's missing mitigations!!
        for x in k['notes']:
            if x['category'] == 'description':
                self.description = x['text']
            if x['category'] == 'summary':
                self.summary = x['text']
            if x['category'] == 'other' and x['title'] == 'Statement':
                self.statement = x['text']

        # external references
        self.references = []
        for x in k['references']:
            if x['category'] == 'self':
                continue
            if x['category'] == 'external':
                self.references.append(x['url'])

        self.cvss_v3 = []
        self.cvss_v2 = []
        for x in k['scores']:
            if 'products' in x:
                filtered_products = filter_products(x['products'])
            if 'cvss_v3' in x:
                self.cvss_v3.append({'scores': x['cvss_v3'], 'products': filtered_products})
            elif 'cvss_v2' in x:
                self.cvss_v2.append({'scores': x['cvss_v2'], 'products': filtered_products})

        self.global_cvss = None
        self.cvss_type = None
        if self.cvss_v3:
            self.cvss_type = 'v3'
            if len(self.cvss_v3) == 1:
                self.global_cvss = self.cvss_v3[0]['scores']
            #else:
            # TODO: something fancy to assign alternate CVSS to other packages
            #print(cvss_v3)

        if self.cvss_v2:
            self.cvss_type = 'v2'
            if len(self.cvss_v2) == 1:
                if not self.global_cvss:
                    self.global_cvss = self.cvss_v2[0]['scores']
            #else:
            # TODO: something fancy like above
            #print(cvss_v2)

        self.impacts = []
        for x in k['threats']:
            if x['category'] == 'impact':
                self.impacts.append({x['details']: filter_products(x['product_ids'])})

        # Impact ratings
        self.global_impact = None
        if len(self.impacts) == 1:
            self.global_impact = list(self.impacts.keys())[0]
        else:
            baseline = 0
            for a in self.impacts:
                sev = list(a.keys())[0]
                if SEVERITY_MAP[sev] > baseline:
                    self.baseline = SEVERITY_MAP[sev]
                    self.global_impact = sev