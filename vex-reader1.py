#!/usr/bin/env python3

# Read and process a VEX document
# i.e. https://access.redhat.com/security/data/csaf/beta/vex/2024/cve-2024-21626.json

import argparse
import os
import json
from vex import Vex
from vex import VexPackages

def main():
    parser = argparse.ArgumentParser(description='VEX Parser')
    parser.add_argument('--vex', dest='vex', metavar="FILE", help='VEX file to process', required=True)
    parser.add_argument('--show-components', dest='show_components', action='store_true', default=False, help='Show components in output')

    args = parser.parse_args()

    if not os.path.exists(args.vex):
        print(f'Missing VEX file: {args.vex}.')
        exit(1)

    with open(args.vex) as fp:
        jdata = json.load(fp)

    vex      = Vex(jdata)
    packages = VexPackages(jdata)

    print(vex.cve)
    print(f'Public on {vex.release_date}')
    print(f'{vex.global_impact} Impact')
    print(f"{vex.global_cvss['baseScore']} CVSS Score")
    print()
    print('Description:')
    print(f'  {vex.description}')
    print()
    if vex.statement:
        print('Statement:')
        print(f'  {vex.statement}')
        #if mitigation:
        print()
        print('Additional Information:')
        print(f'  Bugzilla {vex.bz_id}: {vex.summary}')
        print(f'  {vex.cwe_id}: {vex.cwe_name}')
        print()
        print('External References:')
        for url in vex.references:
            print(f'  {url}')
        print()
        print('Fixed Packages:')
        for x in packages.fixes:
            print(f"  {x.id} -- {x.product}")
            if args.show_components:
                for c in list(set(x.components)):
                    print(f'             {c}')

        print()

        print(f'CVSS {vex.cvss_type} Vector')
        print(f"Red Hat: {vex.global_cvss['vectorString']}")
        print('NVD:     **NOT YET**')
        print()
        print(f'CVSS {vex.cvss_type} Score Breakdown')
        # TODO: string padding
        print('                        Red Hat    NVD')
        print(f"CVSS v3 Base Score      {vex.global_cvss['baseScore']}        0.0")
        print(f"Attack Vector           {vex.global_cvss['attackVector'].capitalize()}")
        print(f"Attack Complexity       {vex.global_cvss['attackComplexity'].capitalize()}")
        print(f"Privileges Required     {vex.global_cvss['privilegesRequired'].capitalize()}")
        print(f"User Interaction        {vex.global_cvss['userInteraction'].capitalize()}")
        print(f"Scope                   {vex.global_cvss['scope'].capitalize()}")
        print(f"Confidentiality Impact  {vex.global_cvss['confidentialityImpact'].capitalize()}")
        print(f"Integrity Impact        {vex.global_cvss['integrityImpact'].capitalize()}")
        print(f"Availability Impact     {vex.global_cvss['availabilityImpact'].capitalize()}")
        print()
        print('Acknowledgements:')
        print(f'  Red Hat would like to thank {vex.acks} for reporting this issue.')


if __name__ == '__main__':
    main()