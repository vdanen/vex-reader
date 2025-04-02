# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from datetime import datetime
import json
import os
import pytz
import re
import requests
from .simplecvss import CVSSv3, CVSSv2

from .constants import (
    SEVERITY_MAP,
    SEVERITIES,
    ARCHES,
    OrderedDict,
    filter_components,
    TZ
)

class Vex(object):
    """
    Class to hold VEX object
    """

    def __init__(self, vexfile):
        # handle loading VEX a few different ways; we can obtain from remote, we can load a file, or we can read JSON

        def is_json(jdata):
            try:
                json.loads(jdata)
            except Exception as e:
                return False
            return True

        def is_dict(jdata):
            if isinstance(jdata, dict):
                return True
            return False

        if is_json(vexfile):
            # we received JSON data that needs to be loaded
            vexdata = vexfile

        elif is_dict(vexfile):
            # we received JSON data that was already loaded and is now a dict
            vexdata = vexfile

        elif 'http' in vexfile:
            # load a remove VEX document
            response = requests.get(f'{vexfile}')
            if response.status_code == 200:
                vexdata = response.json()
            elif response.status_code == 404:
                print(f'Not found: {vexfile}')
                exit(1)
            else:
                print(f'Cannot load {vexfile}')
                print(f'Response code: {response.status_code}')
                exit(1)

        else:
            # load a file
            if not os.path.exists(vexfile):
                print(f'Missing VEX file: {vexfile}.')
                exit(1)

            with open(vexfile) as fp:
                vexdata = json.load(fp)

        if not vexdata:
            print(f'Unable to load VEX data from {vexfile}.')
            exit(1)

        self.raw = vexdata

        self.csaf                 = {'type': '', 'csaf_version': ''}
        self.csaf['type']         = self.raw['document']['category']
        self.csaf['csaf_version'] = self.raw['document']['csaf_version']

        # only support csaf_vex 2.0
        # TODO: should we add support to csaf_security_advisory in the future if nothing else exists?
        if self.csaf['type'] != 'csaf_vex':
            print(f"Sorry, I can only handle csaf_vex 2.0 documents, this one is {self.csaf['type']} {self.csaf['csaf_version']}")
            exit(1)

        self.distribution  = None
        self.global_impact = None
        self.publisher     = None

        # some VEX documents do not have very much information...
        if 'aggregate_severity' in self.raw['document']:
            self.global_impact = self.raw['document']['aggregate_severity']['text'].capitalize()
        if 'distribution' in self.raw['document']:
            if 'text' in self.raw['document']['distribution']:
                self.distribution = self.raw['document']['distribution']['text']

        self.title     = self.raw['document']['title']
        if 'publisher' in self.raw['document']:
            self.publisher = self.raw['document']['publisher']['name']
        if self.raw['document']['tracking']['current_release_date'].endswith('Z'):
            parsed_date = datetime.fromisoformat(self.raw['document']['tracking']['current_release_date'][:-1])
            ud = parsed_date.replace(tzinfo=pytz.timezone('UTC'))
        else:
            ud = datetime.fromisoformat(self.raw['document']['tracking']['current_release_date'])
        self.updated   = ud.astimezone(pytz.timezone(TZ)).strftime('%B %d, %Y at %I:%M:%S %p UTC')

        # Notes build up the bulk of our text, we should include them all
        self.notes = {}
        if 'notes' in self.raw['document']:
            for x in self.raw['document']['notes']:
                if x['category'] not in self.notes:
                    self.notes[x['category']] = {}
                self.notes[x['category']][x['title']] = x['text']

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
            self.title          = None
            self.release_date   = None

            if 'title' in k:
                self.title          = k['title']
            self.cve            = k['cve']
            if 'cwe' in k:
                # TODO https://issues.redhat.com/browse/SECDATA-760 and support for CWE chains
                self.cwe_id     = k['cwe']['id']
                self.cwe_sid    = k['cwe']['id'].split('-')[1]
                self.cwe_name   = k['cwe']['name']
            if 'discovery_date' in k:
                self.discovery_date = k['discovery_date']
            if 'release_date' in k:
                # you'd think this would be mandatory and important but it isn't
                if k['release_date'].endswith('Z'):
                    rd              = datetime.fromisoformat(k['release_date'][:-1])
                    rd              = rd.replace(tzinfo=pytz.timezone('UTC'))
                else:
                    rd              = datetime.fromisoformat(k['release_date'])
                self.release_date   = rd.astimezone(pytz.timezone(TZ)).strftime('%Y-%m-%d')
            else:
                print(f'ERROR: {self.cve} is missing a release date!  This probably should not happen!')

            # exploit information
            self.exploits = []
            if 'threats' in k:
                for x in k['threats']:
                    if x['category'] == 'exploit_status':
                        source = ''
                        url    = ''
                        if x['date'].endswith('Z'):
                            xd = datetime.fromisoformat(x['date'][:-1])
                            xd = xd.replace(tzinfo=pytz.timezone('UTC'))
                        else:
                            xd = datetime.fromisoformat(x['date'])
                        xdate  = xd.astimezone(pytz.timezone(TZ)).strftime('%B %d, %Y')
                        # be clever for CISA
                        if 'CISA' in x['details']:
                            source = 'CISA'
                        if 'http' in x['details']:
                            # extract any urls
                            url = re.search("(?P<url>https?://[^\s]+)", x['details']).group('url')
                        self.exploits.append({'date': xdate, 'details': x['details'], 'url': url, 'source': source})

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
        if 'ids' in k:
            for x in k['ids']:
                if x['system_name'] == 'Red Hat Bugzilla ID':
                    self.bz_id = x['text']
                    self.bz_url = f'https://bugzilla.redhat.com/show_bug.cgi?id={self.bz_id}'

        # Notes including descriptions, summaries, statements as part of the vulnerabilities section
        if 'notes' in k:
            for x in k['notes']:
                if x['category'] not in self.notes:
                    self.notes[x['category']] = {}
                if 'title' in x:
                    self.notes[x['category']][x['title']] = x['text']
                else:
                    self.notes[x['category']]['None'] = x['text']

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
            filtered_products = None
            for x in k['scores']:
                if 'products' in x:
                    filtered_products = filter_components(x['products'])
                if filtered_products and 'cvss_v3' in x:
                    self.cvss_v3.append({'scores': x['cvss_v3'], 'version': x['cvss_v3']['version'], 'products': filtered_products})
                elif filtered_products and 'cvss_v2' in x:
                    self.cvss_v2.append({'scores': x['cvss_v2'], 'products': filtered_products})

        self.global_cvss = CVSSv3(None)

        if self.cvss_v3:
            self.cvss_type = 'v3'
            if len(self.cvss_v3) == 1:
                self.global_cvss = CVSSv3(self.cvss_v3[0]['scores'], self.cvss_v3[0]['version'])
                    #self.cvss_v3[0]['scores']
            #else:
            # TODO: something fancy to assign alternate CVSS to other packages
            #print(cvss_v3)

        if self.cvss_v2:
            self.cvss_type = 'v2'
            if len(self.cvss_v2) == 1:
                if self.global_cvss.version is None:
                    self.global_cvss = CVSSv2(self.cvss_v2[0]['scores'])
                    #self.cvss_v2[0]['scores']
            #else:
            # TODO: something fancy like above
            #print(self.global_cvss)

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
