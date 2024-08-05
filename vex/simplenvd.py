# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from datetime import datetime

class NVD(object):
    """
    Class to hold NVD object
    """

    def __init__(self, nvd_data):
        self.raw                   = nvd_data
        if self.raw == None:
            self.version = 'None'
            self.baseScore             = ''
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
            # v2 placeholders
            self.accessVector          = ''
            self.accessComplexity      = ''
            self.authentication        = ''
        else:
            self.version               = nvd_data['version']

        #        >> > nvd_cve['vulnerabilities'][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']
        #        {'version': '3.0', 'vectorString': 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 'attackVector': 'PHYSICAL',
        #         'attackComplexity': 'HIGH', 'privilegesRequired': 'NONE', 'userInteraction': 'NONE', 'scope': 'UNCHANGED',
        #         'confidentialityImpact': 'HIGH', 'integrityImpact': 'HIGH', 'availabilityImpact': 'HIGH', 'baseScore': 6.4,
        #         'baseSeverity': 'MEDIUM'}
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

        # {'version': '2.0', 'vectorString': 'AV:N/AC:L/Au:N/C:P/I:N/A:N', 'accessVector': 'NETWORK',
        # 'accessComplexity': 'LOW', 'authentication': 'NONE', 'confidentialityImpact': 'PARTIAL',
        # 'integrityImpact': 'NONE', 'availabilityImpact': 'NONE', 'baseScore': 5.0}
        elif self.version == '2.0':
            self.baseScore             = nvd_data['baseScore']
            self.vectorString          = nvd_data['vectorString']
            self.accessVector          = nvd_data['accessVector'].capitalize()
            self.accessComplexity      = nvd_data['accessComplexity'].capitalize()
            self.authentication        = nvd_data['authentication'].capitalize()
            self.confidentialityImpact = nvd_data['confidentialityImpact'].capitalize()
            self.integrityImpact       = nvd_data['integrityImpact'].capitalize()
            self.availabilityImpact    = nvd_data['availabilityImpact'].capitalize()
