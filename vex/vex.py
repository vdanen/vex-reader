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
        self.raw = vexdata

        # some VEX documents do not have very much information...
        if 'aggregate_severity' in self.raw['document']:
            self.global_impact = self.raw['document']['aggregate_severity']['text'].capitalize()
        else:
            self.global_impact = None
        if 'distribution' in self.raw['document']:
            self.distribution = self.raw['document']['distribution']['text']
        else:
            self.distribution = None
        self.title     = self.raw['document']['title']
        self.publisher = self.raw['document']['publisher']['name']

        # Notes build up the bulk of our text, we should include them all
        self.notes = {}
        if 'notes' in self.raw['document']:
            for x in self.raw['document']['notes']:
                if x['category'] not in self.notes:
                    self.notes[x['category']] = ''
                self.notes[x['category']] += f"** {x['title']} **\n {x['text']}\n\n"

        self.parse_vulns()

        if not self.acks:
            # there is another place where acknowledgements can be found as per the spec, apparently
            # looking at you https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssh-rce-2024/csaf/cisco-sa-openssh-rce-2024.json
            if 'acknowledgments' in self.raw['document']:
                for x in self.raw['document']['acknowledgments']:
                    if 'summary' in x:
                        self.acks = x['summary']
        else:
            if self.publisher == 'Red Hat Product Security':
                # throw the Red Hat-ism in here (maybe they could do like Cisco does as one statement?)
                self.acks = f'Red Hat would like to thank {self.acks} for reporting this issue.'

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
            self.bz_id          = None
            self.bz_url         = None

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
        summary   = None
        if 'acknowledgments' in k:
            for x in k['acknowledgments']:
                print(x)
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
        if 'ids' in k:
            for x in k['ids']:
                if x['system_name'] == 'Red Hat Bugzilla ID':
                    self.bz_id = x['text']
                    self.bz_url = f'https://bugzilla.redhat.com/show_bug.cgi?id={self.bz_id}'

        # Notes including descriptions, summaries, statements as part of the vulnerabilities section
        if 'notes' in k:
            for x in k['notes']:
                if x['category'] not in self.notes:
                    self.notes[x['category']] = ''
                self.notes[x['category']] += f"** {x['title']} **\n {x['text']}\n\n"

        # external references
        self.references = []
        if 'references' in k:
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
