# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from .simplecvss import CVSSv2, CVSSv3

class CVE(object):
    """
    Class to hold CVE.org object

    This takes the JSON data from CVE.org's API, i.e.:

    response = requests.get(f'https://cveawg.mitre.org/api/cve/{cve}')
    cve_cve  = response.json()
    if cve_cve['cveMetadata']['cveId'] == cve:
        # we got the right result
        cve = CVE(cve_cve)
    """

    def __init__(self, cve_data):
        self.raw     = cve_data
        self.version = None

        # empty to start
        self.cvss31 = CVSSv3(None, '3.1')
        self.cvss30 = CVSSv3(None, '3.0')
        self.cvss20 = CVSSv2(None, '2.0')

        if self.raw is None:
            return

        if 'metrics' in cve_data['containers']['adp'][0]:
            if 'cvssV3_1' in cve_data['containers']['adp'][0]['metrics'][0]:
                print('3.1')
                self.cvss31 = CVSSv3(cve_data['containers']['adp'][0]['metrics'][0]['cvssV3_1'], '3.1')

            if 'cvssV3_0' in cve_data['containers']['adp'][0]['metrics'][0]:
                print('3.0')
                self.cvss30 = CVSSv3(cve_data['containers']['adp'][0]['metrics'][0]['cvssV3_0'], '3.0')

            if 'cvssV_2' in cve_data['containers']['adp'][0]['metrics'][0]:
                print('2.0')
                self.cvss20 = CVSSv2(cve_data['containers']['adp'][0]['metrics'][0]['cvssV2'], '2.0')
