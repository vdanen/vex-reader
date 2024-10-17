# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from .simplecvss import CVSSv2, CVSSv3

class NVD(object):
    """
    Class to hold NVD object

    This takes the JSON data from NVD's API, i.e.:

    response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}')
    nvd_cve  = response.json()
    if nvd_cve['vulnerabilities'][0]['cve']['id'] == cve:
        # we got the right result
        if 'cvssMetricV31' in nvd_cve['vulnerabilities'][0]['cve']['metrics']:
            nvd = NVD(nvd_cve['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData'])
    """

    def __init__(self, nvd_data):
        self.raw     = nvd_data
        self.version = None

        # empty to start
        self.cvss31 = CVSSv3(None, '3.1')
        self.cvss30 = CVSSv3(None, '3.0')
        self.cvss20 = CVSSv2(None, '2.0')

        if self.raw is None:
            return

        if 'metrics' in nvd_data['vulnerabilities'][0]['cve']:
            if 'cvssMetricV31' in nvd_data['vulnerabilities'][0]['cve']['metrics']:
                self.cvss31 = CVSSv3(nvd_data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData'], '3.1')

            if 'cvssMetricV30' in nvd_data['vulnerabilities'][0]['cve']['metrics']:
                self.cvss30 = CVSSv3(nvd_data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData'], '3.0')

            if 'cvssMetricV2' in nvd_data['vulnerabilities'][0]['cve']['metrics']:
                self.cvss20 = CVSSv2(nvd_data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData'], '2.0')
