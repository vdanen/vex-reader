# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from typing import Optional, Dict, Any
from dataclasses import dataclass, field

@dataclass
class CVSSv2:
    """Class to handle CVSS v2 vulnerability metrics.

    Attributes:
        version: CVSS version (default: 2.0)
        baseScore: Base vulnerability score
        vectorString: CVSS vector string
        accessVector: Network access vector
        accessComplexity: Complexity of attack
        authentication: Authentication requirements
        confidentialityImpact: Impact on confidentiality
        integrityImpact: Impact on integrity
        availabilityImpact: Impact on availability
    """

    version:               Optional[str] = None
    baseScore:             str = field(default='')
    vectorString:          str = field(default='NOT AVAILABLE')
    accessVector:          str = field(default='')
    accessComplexity:      str = field(default='')
    authentication:        str = field(default='')
    confidentialityImpact: str = field(default='')
    integrityImpact:       str = field(default='')
    availabilityImpact:    str = field(default='')

    def __init__(self, metrics: Optional[Dict[str, Any]] = None, version: str = '2.0') -> None:
        """Initialize CVSS v2 metrics.

        Args:
            metrics: Dictionary containing CVSS v2 metric values
            version: CVSS version string (default: '2.0')
        """
        # Set default values
        self.__dict__.update(self.__class__.__dataclass_fields__)  # type: ignore

        if not metrics:
            return

        try:
            self.version      = version
            self.baseScore    = metrics['baseScore']
            self.vectorString = metrics['vectorString']

            # Capitalize all metric values for consistency
            for field in ['accessVector', 'accessComplexity', 'authentication',
                         'confidentialityImpact', 'integrityImpact', 'availabilityImpact']:
                if value := metrics.get(field):
                    setattr(self, field, value.capitalize())

        except (KeyError, AttributeError) as e:
            # Reset to defaults on error
            self.__dict__.update(self.__class__.__dataclass_fields__)  # type: ignore


@dataclass
class CVSSv3:
    """Class to handle CVSS v3 vulnerability metrics.

    Attributes:
        version: CVSS version (default: 3.1)
        baseScore: Base vulnerability score
        vectorString: CVSS vector string
        attackVector: Attack vector type
        attackComplexity: Complexity of attack
        privilegesRequired: Required privileges
        userInteraction: User interaction needed
        scope: Scope of impact
        confidentialityImpact: Impact on confidentiality
        integrityImpact: Impact on integrity
        availabilityImpact: Impact on availability
        baseSeverity: Overall severity rating
    """

    version:               Optional[str] = None
    baseScore:             str = field(default='')
    vectorString:          str = field(default='NOT AVAILABLE')
    attackVector:          str = field(default='')
    attackComplexity:      str = field(default='')
    privilegesRequired:    str = field(default='')
    userInteraction:       str = field(default='')
    scope:                 str = field(default='')
    confidentialityImpact: str = field(default='')
    integrityImpact:       str = field(default='')
    availabilityImpact:    str = field(default='')
    baseSeverity:          str = field(default='')

    def __init__(self, metrics: Optional[Dict[str, Any]] = None, version: str = '3.1') -> None:
        """Initialize CVSS v3 metrics.

        Args:
            metrics: Dictionary containing CVSS v3 metric values
            version: CVSS version string (default: '3.1')
        """
        # Set default values
        self.__dict__.update(self.__class__.__dataclass_fields__)  # type: ignore

        if not metrics:
            return

        try:
            self.version      = version
            self.baseScore    = metrics['baseScore']
            self.vectorString = metrics['vectorString']

            # Capitalize all metric values for consistency
            for field in ['attackVector', 'attackComplexity', 'privilegesRequired',
                         'userInteraction', 'scope', 'confidentialityImpact',
                         'integrityImpact', 'availabilityImpact', 'baseSeverity']:
                if value := metrics.get(field):
                    setattr(self, field, value.capitalize())

        except (KeyError, AttributeError) as e:
            # Reset to defaults on error
            self.__dict__.update(self.__class__.__dataclass_fields__)  # type: ignore
