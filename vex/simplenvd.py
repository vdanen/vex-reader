# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from typing import Optional, Dict, Any
from dataclasses import dataclass
from .simplecvss import CVSSv2, CVSSv3

@dataclass
class NVD:
    """Class to handle NVD vulnerability data.

    Parses and stores CVSS scoring data from NVD's API response.

    Example:
        >>> response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}')
        >>> nvd_data = response.json()
        >>> if nvd_data['vulnerabilities'][0]['cve']['id'] == cve_id:
        >>>     if 'cvssMetricV31' in nvd_data['vulnerabilities'][0]['cve']['metrics']:
        >>>         nvd = NVD(nvd_data)

    Attributes:
        raw: Raw JSON data from NVD API
        cvss31: CVSS 3.1 scoring data
        cvss30: CVSS 3.0 scoring data
        cvss20: CVSS 2.0 scoring data
    """

    raw: Optional[Dict[str, Any]]
    cvss31: CVSSv3
    cvss30: CVSSv3
    cvss20: CVSSv2

    def __init__(self, nvd_data: Optional[Dict[str, Any]] = None) -> None:
        """Initialize NVD object with data from NVD API.

        Args:
            nvd_data: JSON response data from NVD API
        """
        self.raw = nvd_data

        # Initialize empty CVSS objects
        self.cvss31 = CVSSv3(None, '3.1')
        self.cvss30 = CVSSv3(None, '3.0')
        self.cvss20 = CVSSv2(None, '2.0')

        if not nvd_data:
            return

        try:
            metrics = nvd_data['vulnerabilities'][0]['cve'].get('metrics', {})

            # Parse CVSS data if available
            if cvss31_data := metrics.get('cvssMetricV31', [{}])[0].get('cvssData'):
                self.cvss31 = CVSSv3(cvss31_data, '3.1')

            if cvss30_data := metrics.get('cvssMetricV30', [{}])[0].get('cvssData'):
                self.cvss30 = CVSSv3(cvss30_data, '3.0')

            if cvss2_data := metrics.get('cvssMetricV2', [{}])[0].get('cvssData'):
                self.cvss20 = CVSSv2(cvss2_data, '2.0')

        except (KeyError, IndexError) as e:
            # Log error or handle invalid data structure
            pass
