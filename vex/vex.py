# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from datetime import datetime

from .constants import (
    SEVERITY_MAP,
    SEVERITIES,
    ARCHES,
    OrderedDict,
    filter_components,
)

class Vex(object):
    """
    Class to hold VEX object
    """

    def __init__(self, vexdata):
        self.raw           = vexdata
        self.global_impact = self.raw['document']['aggregate_severity']['text'].capitalize()
        self.distribution  = self.raw['document']['distribution']['text']
        self.title         = self.raw['document']['title']
        self.publisher     = self.raw['document']['publisher']['name']

        self.parse_vulns()

    def parse_vulns(self):
        """
        Parse base vulnerability characteristics
        :return:
        """

        for k in self.raw['vulnerabilities']:
            # defaults
            self.cwe_id         = None
            self.cwe_name       = None
            self.description    = None
            self.summary        = None
            self.statement      = None
            self.discovery_date = None

            self.title          = k['title']
            self.cve            = k['cve']
            if 'cwe' in k:
                self.cwe_id     = k['cwe']['id']
                self.cwe_name   = k['cwe']['name']
            if 'discovery_date' in k:
                self.discovery_date = k['discovery_date']
            rd                  = datetime.fromisoformat(k['release_date'])
            self.release_date   = rd.astimezone().strftime('%Y-%m-%d') # TODO: force this to be Eastern

        # Acknowledgements
        self.acks = None
        if 'acknowledgments' in k:
            for x in k['acknowledgments']:
                # we should always have names, but may not always have an organization
                # (if the credit is to an org, the org is the name)
                if 'organization' not in x:
                    x['organization'] = ''
                ack_list = {'names': x['names'], 'org': x['organization']}
                if len(ack_list['names']) > 1:
                    # TODO: if there's 2, we can 'and' if there's more than 2 it should be '1, 2 and 3'
                    names = " and ".join(ack_list['names'])
                else:
                    names = ack_list['names'][0]

                if ack_list['org'] == '':
                    self.acks = names
                else:
                    self.acks = f"{names} ({ack_list['org']})"

        # Bugzilla / bugtracking
        for x in k['ids']:
            if x['system_name'] == 'Red Hat Bugzilla ID':
              self.bz_id = x['text']
              self.bz_url = f'https://bugzilla.redhat.com/show_bug.cgi?id={self.bz_id}'

        # Notes including descriptions, summaries, statements
        self.description = None
        self.summary     = None
        self.statement   = None

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
        if 'scores' in k:
            for x in k['scores']:
                if 'products' in x:
                    filtered_products = filter_components(x['products'])
                if 'cvss_v3' in x:
                    self.cvss_v3.append({'scores': x['cvss_v3'], 'products': filtered_products})
                elif 'cvss_v2' in x:
                    self.cvss_v2.append({'scores': x['cvss_v2'], 'products': filtered_products})

        self.global_cvss = None
        self.cvss_type   = None
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

        self.impacts = {'Critical': [], 'Important': [], 'Moderate': [], 'Low': []}
        if 'threats' in k:
            for x in k['threats']:
                if x['category'] == 'impact':
                    # need to map impacts to products
                    for y in filter_components(x['product_ids']):
                        self.impacts[x['details']].append(y)
                    #self.impacts.append({x['details']: filter_products(x['product_ids'])})

        # we can drop those that match the "global" impact by setting the list to empty
        self.impacts[self.global_impact] = []
