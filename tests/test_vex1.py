from unittest import TestCase
import json
from vex import Vex

class TestVex(TestCase):
    def setUp(self):
        with open('./cve-2024-40951.json') as fp:
            jdata = json.load(fp)

        self.vex = Vex(jdata)
        #self.fail()

class TestCVE(TestVex):
    def test_cve_name(self):
        self.assertEqual(self.vex.cve, 'CVE-2024-40951')

    def test_public_date(self):
        self.assertEqual(self.vex.release_date, '2024-07-11')

    def test_impact(self):
        self.assertEqual(self.vex.global_impact, 'Moderate')

    def test_bzid(self):
        self.assertEqual(self.vex.bz_id, '2297535')