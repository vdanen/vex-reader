import os
import sys
from unittest import TestCase
import json
import requests

# Add the parent directory to the path so we can import vex
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vex import Vex
from vex import VexPackages
from vex import NVD

class TestVex(TestCase):
    pass


class TestCVE_2024_40951(TestVex):
    def setUp(self):
        # Use the correct path relative to the tests directory
        test_file = os.path.join(os.path.dirname(__file__), 'cve-2024-40951.json')
        self.vex      = Vex(test_file)
        self.packages = VexPackages(self.vex.raw)

    def test_cve_name(self):
        self.assertEqual(self.vex.cve, 'CVE-2024-40951')

    def test_public_date(self):
        self.assertEqual(self.vex.release_date, '2024-07-11')

    def test_impact(self):
        self.assertEqual(self.vex.global_impact, 'Moderate')

    def test_bzid(self):
        self.assertEqual(self.vex.bz_id, '2297535')

    def test_cvss_vector(self):
        self.assertEqual(self.vex.global_cvss.vectorString, 'NOT AVAILABLE ')

    def test_cvss_base_score(self):
        self.assertEqual(self.vex.global_cvss.baseScore, '')

    def test_number_of_refs(self):
        self.assertEqual(len(self.vex.references), 4)

    def test_number_of_mitigations(self):
        self.assertEqual(len(self.packages.mitigation), 0)

    def test_number_of_fixes(self):
        self.assertEqual(len(self.packages.fixes), 0)

    def test_number_of_noaffects(self):
        self.assertEqual(len(self.packages.not_affected), 7)


class TestCVE_2024_21626(TestVex):
    def setUp(self):
        # Use the correct path relative to the tests directory
        test_file = os.path.join(os.path.dirname(__file__), 'cve-2024-21626.json')
        self.vex      = Vex(test_file)
        self.packages = VexPackages(self.vex.raw)

    def test_cve_name(self):
        self.assertEqual(self.vex.cve, 'CVE-2024-21626')

    def test_public_date(self):
        self.assertEqual(self.vex.release_date, '2024-01-31')

    def test_impact(self):
        self.assertEqual(self.vex.global_impact, 'Important')

    def test_bzid(self):
        self.assertEqual(self.vex.bz_id, '2258725')

    def test_cvss_vector(self):
        self.assertEqual(self.vex.global_cvss.vectorString, 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H')

    def test_cvss_base_score(self):
        self.assertEqual(self.vex.global_cvss.baseScore, 8.6)

    def test_nvd_cvss_vector(self):
        response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-21626')
        self.nvd_cve  = response.json()
        if self.nvd_cve['vulnerabilities'][0]['cve']['id'] == 'CVE-2024-21626':
            # we got the right result
            self.nvd = NVD(self.nvd_cve)
        else:
            self.nvd = NVD(None)
        self.assertEqual(self.nvd.cvss31.vectorString, 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H')

    def test_nvd_cvss_base_score(self):
        response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-21626')
        self.nvd_cve  = response.json()
        if self.nvd_cve['vulnerabilities'][0]['cve']['id'] == 'CVE-2024-21626':
            # we got the right result
            self.nvd = NVD(self.nvd_cve)
        else:
            self.nvd = NVD(None)
        self.assertEqual(self.nvd.cvss31.baseScore, 8.6)

    def test_number_of_refs(self):
        self.assertEqual(len(self.vex.references), 4)

    def test_number_of_mitigations(self):
        self.assertEqual(len(self.packages.mitigation), 1)

    def test_number_of_fixes(self):
        self.assertEqual(len(self.packages.fixes), 17)

    def test_number_of_noaffects(self):
        self.assertEqual(len(self.packages.not_affected), 25)


class TestCVE_2002_0803(TestVex):
    def setUp(self):
        # Use the correct path relative to the tests directory
        test_file = os.path.join(os.path.dirname(__file__), 'cve-2002-0803.json')
        self.vex      = Vex(test_file)
        self.packages = VexPackages(self.vex.raw)

    def test_cve_name(self):
        self.assertEqual(self.vex.cve, 'CVE-2002-0803')

    def test_public_date(self):
        self.assertEqual(self.vex.release_date, '2002-06-07')

    def test_impact(self):
        self.assertEqual(self.vex.global_impact, 'None')

    def test_bzid(self):
        self.assertEqual(self.vex.bz_id, '1616805')

    def test_cvss_vector(self):
        self.assertEqual(self.vex.global_cvss.vectorString, 'NOT AVAILABLE ')

    def test_cvss_base_score(self):
        self.assertEqual(self.vex.global_cvss.baseScore, '')

    def test_number_of_refs(self):
        self.assertEqual(len(self.vex.references), 3)

    def test_number_of_mitigations(self):
        self.assertEqual(len(self.packages.mitigation), 0)

    def test_number_of_fixes(self):
        self.assertEqual(len(self.packages.fixes), 1)

    def test_number_of_noaffects(self):
        self.assertEqual(len(self.packages.not_affected), 0)


class TestCVE_2021_44228(TestVex):
    def setUp(self):
        # Use the correct path relative to the tests directory
        test_file = os.path.join(os.path.dirname(__file__), 'CVE-2021-44228.json')
        self.vex      = Vex(test_file)
        self.packages = VexPackages(self.vex.raw)

    def test_cve_name(self):
        self.assertEqual(self.vex.cve, 'CVE-2021-44228')

    def test_public_date(self):
        self.assertEqual(self.vex.release_date, '2021-12-09')

    def test_impact(self):
        self.assertEqual(self.vex.global_impact, 'Critical')

    def test_bzid(self):
        self.assertEqual(self.vex.bz_id, '2030932')

    def test_cvss_vector(self):
        self.assertEqual(self.vex.global_cvss.vectorString, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')

    def test_cvss_base_score(self):
        self.assertEqual(self.vex.global_cvss.baseScore, 9.8)

    def test_nvd_cvss_vector(self):
        response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228')
        self.nvd_cve  = response.json()
        if self.nvd_cve['vulnerabilities'][0]['cve']['id'] == 'CVE-2021-44228':
            # we got the right result
            self.nvd = NVD(self.nvd_cve)
        else:
            self.nvd = NVD(None)
        self.assertEqual(self.nvd.cvss31.vectorString, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')

    def test_nvd_cvss_base_score(self):
        response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228')
        self.nvd_cve  = response.json()
        if self.nvd_cve['vulnerabilities'][0]['cve']['id'] == 'CVE-2021-44228':
            # we got the right result
            self.nvd = NVD(self.nvd_cve)
        else:
            self.nvd = NVD(None)
        self.assertEqual(self.nvd.cvss31.baseScore, 10.0)

    def test_number_of_refs(self):
        self.assertEqual(len(self.vex.references), 8)

    def test_number_of_mitigations(self):
        self.assertEqual(len(self.packages.mitigation), 1)

    def test_number_of_fixes(self):
        self.assertEqual(len(self.packages.fixes), 23)

    def test_number_of_noaffects(self):
        self.assertEqual(len(self.packages.not_affected), 130)


"""
class TestCVE_Cisco_rce_2024(TestVex):
    def setUp(self):
        test_file = os.path.join(os.path.dirname(__file__), 'cisco-sa-openssh-rce-2024.json')
        self.vex      = Vex(test_file)
        self.packages = VexPackages(self.vex.raw)

    def test_cve_name(self):
        self.assertEqual(self.vex.cve, 'CVE-2024-6387')

    def test_public_date(self):
        self.assertEqual(self.vex.release_date, '2024-07-02')

    def test_impact(self):
        self.assertIsNone(self.vex.global_impact)

    def test_bzid(self):
        self.assertIsNone(self.vex.bz_id)

    def test_cvss_vector(self):
        self.assertEqual(self.vex.global_cvss['vectorString'], 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H')

    def test_number_of_refs(self):
        self.assertEqual(len(self.vex.references), 0)

    def test_number_of_mitigations(self):
        self.assertEqual(len(self.packages.mitigation), 0)

    def test_number_of_fixes(self):
        self.assertEqual(len(self.packages.fixes), 1)

    def test_number_of_noaffects(self):
        self.assertEqual(len(self.packages.not_affected), 0)

"""
