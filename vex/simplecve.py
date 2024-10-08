# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

class CVE(object):
    """
    Class to hold CVE.org object

    #TODO: refactor this so we can do like comparisons; i.e. if the VEX has CVSSv2 and NVD has v2 and v3, we should show
    #something similar to what VEX has, or at least expose all the scores maybe as nvd.v30.baseScore, etc
    """

    def __init__(self, cve_data):
        self.raw     = cve_data
        self.version = None

        if 'metrics' in cve_data['containers']['adp'][0]:
            if 'cvssV3_1' in cve_data['containers']['adp'][0]['metrics'][0]:
                c_data = cve_data['containers']['adp'][0]['metrics'][0]['cvssV3_1']
                self.version = '3.1'
            elif 'cvssV3_0' in cve_data['containers']['adp'][0]['metrics'][0]:
                c_data = cve_data['containers']['adp'][0]['metrics'][0]['cvssV3_0']
                self.version = '3.0'
            elif 'cvssV_2' in cve_data['containers']['adp'][0]['metrics'][0]:
                c_data = cve_data['containers']['adp'][0]['metrics'][0]['cvssV2']
                self.version = '2.0'

        if self.version == '3.1':
            self.baseScore             = c_data['baseScore']
            self.vectorString          = c_data['vectorString']
            self.attackVector          = c_data['attackVector'].capitalize()
            self.attackComplexity      = c_data['attackComplexity'].capitalize()
            self.privilegesRequired    = c_data['privilegesRequired'].capitalize()
            self.userInteraction       = c_data['userInteraction'].capitalize()
            self.scope                 = c_data['scope'].capitalize()
            self.confidentialityImpact = c_data['confidentialityImpact'].capitalize()
            self.integrityImpact       = c_data['integrityImpact'].capitalize()
            self.availabilityImpact    = c_data['availabilityImpact'].capitalize()
            self.baseSeverity          = c_data['baseSeverity'].capitalize()

        elif self.version == '3.0':
            self.baseScore             = c_data['baseScore']
            self.vectorString          = c_data['vectorString']
            self.attackVector          = c_data['attackVector'].capitalize()
            self.attackComplexity      = c_data['attackComplexity'].capitalize()
            self.privilegesRequired    = c_data['privilegesRequired'].capitalize()
            self.userInteraction       = c_data['userInteraction'].capitalize()
            self.scope                 = c_data['scope'].capitalize()
            self.confidentialityImpact = c_data['confidentialityImpact'].capitalize()
            self.integrityImpact       = c_data['integrityImpact'].capitalize()
            self.availabilityImpact    = c_data['availabilityImpact'].capitalize()
            self.baseSeverity          = c_data['baseSeverity'].capitalize()

        elif self.version == '2.0':
            self.baseScore             = c_data['baseScore']
            self.vectorString          = c_data['vectorString']
            self.accessVector          = c_data['accessVector'].capitalize()
            self.accessComplexity      = c_data['accessComplexity'].capitalize()
            self.authentication        = c_data['authentication'].capitalize()
            self.confidentialityImpact = c_data['confidentialityImpact'].capitalize()
            self.integrityImpact       = c_data['integrityImpact'].capitalize()
            self.availabilityImpact    = c_data['availabilityImpact'].capitalize()

        else:
            self.version               = None
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
