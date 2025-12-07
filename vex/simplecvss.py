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
            self.version      = version
            self.baseScore    = metrics['baseScore']
            self.vectorString = metrics['vectorString']
            # not all VEX files may break out the specific metrics
            if 'accessVector' in metrics:
                self.accessVector          = metrics['accessVector'].capitalize()
                self.accessComplexity      = metrics['accessComplexity'].capitalize()
                self.authentication        = metrics['authentication'].capitalize()
                self.confidentialityImpact = metrics['confidentialityImpact'].capitalize()
                self.integrityImpact       = metrics['integrityImpact'].capitalize()
                self.availabilityImpact    = metrics['availabilityImpact'].capitalize()
            else:
                # derive these from the metrics
                metriclist = metrics['vectorString'].split('/')
                for m in metriclist:
                    if m.startswith('AV:'):
                        key = {'N': 'Network', 'A': 'Adjacent', 'L': 'Local'}
                        self.accessVector = key[m.split(':')[1]]
                    if m.startswith('AC:'):
                        key = {'H': 'High', 'M': 'Medium', 'L': 'Low'}
                        self.accessComplexity = key[m.split(':')[1]]
                    if m.startswith('Au:'):
                        key = {'M': 'Multiple', 'S': 'Single', 'N': 'None'}
                        self.authentication = key[m.split(':')[1]]
                    if m.startswith('C:'):
                        key = {'C': 'Complete', 'P': 'Partial', 'N': 'None'}
                        self.confidentialityImpact = key[m.split(':')[1]]
                    if m.startswith('I:'):
                        key = {'C': 'Complete', 'P': 'Partial', 'N': 'None'}
                        self.integrityImpact = key[m.split(':')[1]]
                    if m.startswith('A:'):
                        key = {'C': 'Complete', 'P': 'Partial', 'N': 'None'}
                        self.availabilityImpact = key[m.split(':')[1]]


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
            self.version      = version
            self.baseScore    = metrics['baseScore']
            self.vectorString = metrics['vectorString']
            self.baseSeverity = metrics['baseSeverity'].capitalize()
            # not all VEX files may break out the specific metrics
            if 'attackVector' in metrics:
                self.attackVector          = metrics['attackVector'].capitalize()
                self.attackComplexity      = metrics['attackComplexity'].capitalize()
                self.privilegesRequired    = metrics['privilegesRequired'].capitalize()
                self.userInteraction       = metrics['userInteraction'].capitalize()
                self.scope                 = metrics['scope'].capitalize()
                self.confidentialityImpact = metrics['confidentialityImpact'].capitalize()
                self.integrityImpact       = metrics['integrityImpact'].capitalize()
                self.availabilityImpact    = metrics['availabilityImpact'].capitalize()
            else:
                # derive these from the metrics
                metriclist = metrics['vectorString'].split('/')
                for m in metriclist:
                    if m.startswith('AV:'):
                        key = {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'}
                        self.attackVector = key[m.split(':')[1]]
                    if m.startswith('AC:'):
                        key = {'H': 'High', 'L': 'Low'}
                        self.attackComplexity = key[m.split(':')[1]]
                    if m.startswith('PR:'):
                        key = {'H': 'High', 'L': 'Low', 'N': 'None'}
                        self.privilegesRequired = key[m.split(':')[1]]
                    if m.startswith('UI:'):
                        key = {'R': 'Required', 'N': 'None'}
                        self.userInteraction = key[m.split(':')[1]]
                    if m.startswith('S:'):
                        key = {'U': 'Unchanged', 'C': 'Changed'}
                        self.scope = key[m.split(':')[1]]
                    if m.startswith('C:'):
                        key = {'H': 'High', 'L': 'Low', 'N': 'None'}
                        self.confidentialityImpact = key[m.split(':')[1]]
                    if m.startswith('I:'):
                        key = {'H': 'High', 'L': 'Low', 'N': 'None'}
                        self.integrityImpact = key[m.split(':')[1]]
                    if m.startswith('A:'):
                        key = {'H': 'High', 'L': 'Low', 'N': 'None'}
                        self.availabilityImpact = key[m.split(':')[1]]
