# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

class CVSSv2(object):
    """
    Class to hold CVSSv2 metrics
    """
    def __init__(self, metrics, version='2.0'):
        self.version               = None
        self.baseScore             = ''
        self.vectorString          = 'NOT AVAILABLE '
        self.accessVector          = ''
        self.accessComplexity      = ''
        self.authentication        = ''
        self.confidentialityImpact = ''
        self.integrityImpact       = ''
        self.availabilityImpact    = ''

        if metrics is not None:
            self.version               = version
            self.baseScore             = metrics['baseScore']
            self.vectorString          = metrics['vectorString']
            self.accessVector          = metrics['accessVector'].capitalize()
            self.accessComplexity      = metrics['accessComplexity'].capitalize()
            self.authentication        = metrics['authentication'].capitalize()
            self.confidentialityImpact = metrics['confidentialityImpact'].capitalize()
            self.integrityImpact       = metrics['integrityImpact'].capitalize()
            self.availabilityImpact    = metrics['availabilityImpact'].capitalize()


class CVSSv3(object):
    """
    Class to hold CVSSv3 metrics
    """

    def __init__(self, metrics, version='3.1'):
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

        if metrics is not None:
            self.version               = version
            self.baseScore             = metrics['baseScore']
            self.vectorString          = metrics['vectorString']
            self.attackVector          = metrics['attackVector'].capitalize()
            self.attackComplexity      = metrics['attackComplexity'].capitalize()
            self.privilegesRequired    = metrics['privilegesRequired'].capitalize()
            self.userInteraction       = metrics['userInteraction'].capitalize()
            self.scope                 = metrics['scope'].capitalize()
            self.confidentialityImpact = metrics['confidentialityImpact'].capitalize()
            self.integrityImpact       = metrics['integrityImpact'].capitalize()
            self.availabilityImpact    = metrics['availabilityImpact'].capitalize()
            self.baseSeverity          = metrics['baseSeverity'].capitalize()
