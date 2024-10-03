#!/usr/bin/env python3

# Simple demo script to show getting some severity counts for CVES
# It doesn't do anything fancy when you point it to a single VEX document, but looks useful when you point it to a directory
#
# i.e. https://security.redhat.com/data/csaf/v2/vex/2024/cve-2024-21626.json

import argparse
from gc import get_stats

import os
from rich.console import Console
from vex import Vex
from vex.constants import SEVERITY_COLOR


def get_stats(file, stats):
    vex = Vex(file)
    rd  = vex.release_date
    if vex.global_impact:
        sev = vex.global_impact
    else:
        sev = None

    year = rd[:4]

    if year not in stats:
        stats[year] = {'Critical': [], 'Important': [], 'Moderate': [], 'Low': [], 'None': []}

    if sev:
        stats[year][sev].append(vex.cve)
    else:
        stats[year]['None'].append(vex.cve)

    return stats


def main():
    parser = argparse.ArgumentParser(description='Count severities of CVEs in VEX')
    parser.add_argument('--vex', dest='vex', metavar="FILE", help='VEX file or directory of VEX files to process', required=True)
    parser.add_argument('--year', dest='only_year', metavar="YEAR", default=False, help='Restrict output to only show released this year')
    parser.add_argument('--cves', dest='include_cves', action='store_true', default=False, help='Additionally include CVE list')

    args = parser.parse_args()

    console  = Console()
    stats    = {}

    if os.path.isfile(args.vex):
        print(args.vex)
        stats = get_stats(args.vex, stats)
        print(stats)

    if os.path.isdir(args.vex):
        print(f'Showing statistics for {args.vex}\n')
        for file in os.listdir(args.vex):
            stats = get_stats(args.vex + '/' + file, stats)

        for y in sorted(stats.keys()):
            c = len(stats[y]['Critical'])
            i = len(stats[y]['Important'])
            m = len(stats[y]['Moderate'])
            l = len(stats[y]['Low'])
            line = f"Critical: [{SEVERITY_COLOR['Critical']}]{c:2}[/{SEVERITY_COLOR['Critical']}], Important: [{SEVERITY_COLOR['Important']}]{i:3}[/{SEVERITY_COLOR['Important']}], Moderate: [{SEVERITY_COLOR['Moderate']}]{m:4}[/{SEVERITY_COLOR['Moderate']}], Low: [{SEVERITY_COLOR['Low']}]{l:3}[/{SEVERITY_COLOR['Low']}]"
            total = c + i + m + l
            if args.only_year and args.only_year == y:
                console.print(f'{y}: {line} -- TOTAL: {total}')
            elif not args.only_year:
                console.print(f'{y}: {line} -- TOTAL: {total}')


if __name__ == '__main__':
    main()