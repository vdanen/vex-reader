#!/usr/bin/env python3

# Read and process a VEX document
# i.e. https://access.redhat.com/security/data/csaf/beta/vex/2024/cve-2024-21626.json

import argparse
import os
import json
import requests
from vex import Vex
from vex import VexPackages
from vex import NVD

def main():
    parser = argparse.ArgumentParser(description='VEX Parser')
    parser.add_argument('--vex', dest='vex', metavar="FILE", help='VEX file to process', required=True)
    parser.add_argument('--show-components', dest='show_components', action='store_true', default=False, help='Show components in output')
    parser.add_argument('--no-nvd', dest='no_nvd', action='store_true', default=False, help='Avoid API calls to NVD')

    args = parser.parse_args()

    if not os.path.exists(args.vex):
        print(f'Missing VEX file: {args.vex}.')
        exit(1)

    with open(args.vex) as fp:
        jdata = json.load(fp)

    vex      = Vex(jdata)
    packages = VexPackages(jdata)

    if args.no_nvd:
        nvd = NVD(None)
    else:
        response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={vex.cve}')
        nvd_cve  = response.json()
        if nvd_cve['vulnerabilities'][0]['cve']['id'] == vex.cve:
            # we got the right result
            if 'cvssMetricV31' in nvd_cve['vulnerabilities'][0]['cve']['metrics']:
                nvd = NVD(nvd_cve['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData'])
            elif 'cvssMetricV30' in nvd_cve['vulnerabilities'][0]['cve']['metrics']:
                nvd = NVD(nvd_cve['vulnerabilities'][0]['cve']['metrics']['cvssMetricV30'][0]['cvssData'])
            elif 'cvssMetricV2' in nvd_cve['vulnerabilities'][0]['cve']['metrics']:
                nvd = NVD(nvd_cve['vulnerabilities'][0]['cve']['metrics']['cvssMetricV2'][0]['cvssData'])
            else:
                nvd = NVD(None)

    print(vex.cve)
    print('-' * len(vex.cve))
    print()
    print(f'Public on : {vex.release_date}')
    if vex.global_impact:
        print(f'Impact    : {vex.global_impact}')
    if vex.global_cvss:
        print(f"CVSS Score: {vex.global_cvss['baseScore']}")
    print()

    # print the notes from the VEX document
    if 'summary' in vex.notes:
        print(vex.notes['summary'])
    if 'description' in vex.notes:
        print(vex.notes['description'])
    if 'general' in vex.notes:
        print(vex.notes['general'])
    if 'legal_disclaimer' in vex.notes:
        print(vex.notes['legal_disclaimer'])
    print()

    if vex.statement:
        print('Statement:')
        print(f'  {vex.statement}')
        print()

    mitigation = None
    if packages.mitigation:
        print('Mitigation:')
        if len(packages.mitigation) > 1:
            print('**WARNING**: MORE THAN ONE MITIGATION DISCOVERED!')
        for x in packages.mitigation:
            print(f'  {x.details}')
        print()

    refs = []
    if vex.bz_id:
        refs.append(f'  Bugzilla {vex.bz_id}: {vex.summary}')
    if vex.cwe_id:
        refs.append(f'  {vex.cwe_id}: {vex.cwe_name}')
    if refs:
        print('Additional Information:')
        for r in refs:
            print(r)
    print()

    if vex.references:
        print('External References:')
        for url in vex.references:
            print(f'  {url}')
        print()

    vendor = 'Unknown'
    if packages.fixes:
        # the vendor for Red Hat VEX is Red Hat Product Security which isn't right,
        # so we'll override until there's a fix
        if vex.publisher == 'Red Hat Product Security':
            publisher = 'Red Hat'
        else:
            publisher = vex.publisher

        print(f'{publisher} affected packages and issued errata:')
        for x in packages.fixes:
            print(f"  {x.id} -- {x.product}")
            if args.show_components:
                for c in list(set(x.components)):
                    print(f'             {c}')
        print()

    if packages.not_affected:
        print('Packages that are not affected:')
        for x in packages.not_affected:
            print(f"  {x.product} ({', '.join(x.components)})")
        print()

    if packages.wontfix:
        print('Affected packages without fixes:')
        for x in packages.wontfix:
            print(f"  {x.product} ({x.component}): {x.reason}")
        print()

    if vex.global_cvss:
        print(f'CVSS {vex.cvss_type} Vector')
        plen = 4
        if len(publisher) > 4:
            plen = len(publisher)
        print(f"  {publisher:{plen}}: {vex.global_cvss['vectorString']}")
        if not args.no_nvd:
            print(f'  {"NVD":{plen}}: {nvd.vectorString}')
        print()

        print(f'CVSS {vex.cvss_type} Score Breakdown')
        # TODO: string padding
        print(f'{' ':26} {publisher:<10} NVD')
        if vex.cvss_type == 'v3':
            print(f"  {'CVSS v3 Base Score':24} {vex.global_cvss['baseScore']:<10} {nvd.baseScore}")
            if 'attackVector' in vex.global_cvss:
                # not all VEX will break down the metrics
                print(f"  {'Attack Vector':24} {vex.global_cvss['attackVector'].capitalize():10} {nvd.attackVector}")
                print(f"  {'Attack Complexity':24} {vex.global_cvss['attackComplexity'].capitalize():10} {nvd.attackComplexity}")
                print(f"  {'Privileges Required':24} {vex.global_cvss['privilegesRequired'].capitalize():10} {nvd.privilegesRequired}")
                print(f"  {'User Interaction':24} {vex.global_cvss['userInteraction'].capitalize():10} {nvd.userInteraction}")
                print(f"  {'Scope':24} {vex.global_cvss['scope'].capitalize():10} {nvd.scope}")
        elif vex.cvss_type == 'v2':
            print(f"  {'CVSS v2 Base Score':24} {vex.global_cvss['baseScore']:<10} {nvd.baseScore}")
            if 'accessVector' in vex.global_cvss:
                # not all VEX will break down the metrics
                print(f"  {'Access Vector':24} {vex.global_cvss['accessVector'].capitalize():10} {nvd.accessVector}")
                print(f"  {'Access Complexity':24} {vex.global_cvss['accessComplexity'].capitalize():10} {nvd.accessComplexity}")
                print(f"  {'Authentication':24} {vex.global_cvss['authentication'].capitalize():10} {nvd.authentication}")
        if 'confidentialityImpact' in vex.global_cvss:
            # not all VEX will break down the metrics
            print(f"  {'Confidentiality Impact':24} {vex.global_cvss['confidentialityImpact'].capitalize():10} {nvd.confidentialityImpact}")
            print(f"  {'Integrity Impact':24} {vex.global_cvss['integrityImpact'].capitalize():10} {nvd.integrityImpact}")
            print(f"  {'Availability Impact':24} {vex.global_cvss['availabilityImpact'].capitalize():10} {nvd.availabilityImpact}")
        print()

    if vex.acks:
        print('Acknowledgements:')
        print(f'  {vex.acks}')
        print()

    if vex.distribution:
        print(vex.distribution)

if __name__ == '__main__':
    main()