# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from datetime import datetime

class NVD(object):
    """
    Class to hold NVD object
    """

    def __init__(self, nvd_data):
        #        >> > nvd_cve['vulnerabilities'][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']
        #        {'version': '3.0', 'vectorString': 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 'attackVector': 'PHYSICAL',
        #         'attackComplexity': 'HIGH', 'privilegesRequired': 'NONE', 'userInteraction': 'NONE', 'scope': 'UNCHANGED',
        #         'confidentialityImpact': 'HIGH', 'integrityImpact': 'HIGH', 'availabilityImpact': 'HIGH', 'baseScore': 6.4,
        #         'baseSeverity': 'MEDIUM'}

        self.raw                   = nvd_data
        if self.raw == None:
            self.version = 'None'
            self.baseScore             = '0.0'
            self.vectorString          = 'NOT AVAILABLE '
            self.attackVector          = ''
            self.attackComplexity      = ''
            self.privilegesRequired    = ''
            self.userInteraction       = ''
            self.scope                 = ''
            self.confidentialityImpact = ''
            self.integrityImpact       = ''
            self.availabilityImpact    = ''
            self.baseSeverity          = ''

        self.version               = nvd_data['version']
        if self.version == '3.0':
            self.baseScore             = nvd_data['baseScore']
            self.vectorString          = nvd_data['vectorString']
            self.attackVector          = nvd_data['attackVector'].capitalize()
            self.attackComplexity      = nvd_data['attackComplexity'].capitalize()
            self.privilegesRequired    = nvd_data['privilegesRequired'].capitalize()
            self.userInteraction       = nvd_data['userInteraction'].capitalize()
            self.scope                 = nvd_data['scope'].capitalize()
            self.confidentialityImpact = nvd_data['confidentialityImpact'].capitalize()
            self.integrityImpact       = nvd_data['integrityImpact'].capitalize()
            self.availabilityImpact    = nvd_data['availabilityImpact'].capitalize()
            self.baseSeverity          = nvd_data['baseSeverity'].capitalize()

