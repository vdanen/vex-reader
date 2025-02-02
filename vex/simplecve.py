# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from typing import Optional, Dict, Any
from dataclasses import dataclass
from .simplecvss import CVSSv2, CVSSv3

@dataclass
class CVE:
    """Class to handle CVE.org vulnerability data.

    Parses and stores CVSS scoring data from CVE.org's API response.

    Example:
        >>> response = requests.get(f'https://cveawg.mitre.org/api/cve/{cve_id}')
        >>> cve_data = response.json()
        >>> if cve_data['cveMetadata']['cveId'] == cve_id:
        >>>     cve = CVE(cve_data)

    Attributes:
        raw: Raw JSON data from CVE.org API
        cvss31: CVSS 3.1 scoring data
        cvss30: CVSS 3.0 scoring data
        cvss20: CVSS 2.0 scoring data
    """

    raw: Optional[Dict[str, Any]]
    cvss31: CVSSv3
    cvss30: CVSSv3
    cvss20: CVSSv2

    def __init__(self, cve_data: Optional[Dict[str, Any]] = None) -> None:
        """Initialize CVE object with data from CVE.org API.

        Args:
            cve_data: JSON response data from CVE.org API
        """
        self.raw = cve_data

        # Initialize empty CVSS objects
        self.cvss31 = CVSSv3(None, '3.1')
        self.cvss30 = CVSSv3(None, '3.0')
        self.cvss20 = CVSSv2(None, '2.0')

        if not cve_data:
            return

        try:
            metrics = cve_data['containers']['adp'][0].get('metrics', [{}])[0]

            # Parse CVSS data if available
            if cvss31_data := metrics.get('cvssV3_1'):
                self.cvss31 = CVSSv3(cvss31_data, '3.1')

            if cvss30_data := metrics.get('cvssV3_0'):
                self.cvss30 = CVSSv3(cvss30_data, '3.0')

            if cvss2_data := metrics.get('cvssV2'):
                self.cvss20 = CVSSv2(cvss2_data, '2.0')

        except (KeyError, IndexError) as e:
            # Log error or handle invalid data structure
            pass
