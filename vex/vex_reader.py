# Read and process a VEX document
# i.e. https://access.redhat.com/security/data/csaf/beta/vex/2024/cve-2024-21626.json

import argparse
import requests
from rich.console import Console
from rich.markdown import Markdown

from .vex import Vex
from .package import VexPackages
from .simplenvd import NVD
from .constants import SEVERITY_COLOR


def main():
    parser = argparse.ArgumentParser(description='VEX Parser')
    parser.add_argument('--vex', dest='vex', metavar="FILE", help='VEX file to process', required=True)
    parser.add_argument('--show-components', dest='show_components', action='store_true', default=False, help='Show components in output')
    parser.add_argument('--no-nvd', dest='no_nvd', action='store_true', default=False, help='Avoid API calls to NVD')

    args = parser.parse_args()

    console  = Console()
    vex      = Vex(args.vex)
    packages = VexPackages(vex.raw)  # we need the raw json data

    if args.no_nvd:
        nvd = NVD(None)
    else:
        response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={vex.cve}')
        nvd_cve  = response.json()
        #print(nvd_cve)
        if nvd_cve['vulnerabilities'][0]['cve']['id'] == vex.cve:
            # we got the right result
            nvd = NVD(nvd_cve)
        else:
            nvd = NVD(None)

    console.print(f'[bold red]{vex.cve}[/bold red]')
    print('-' * len(vex.cve))
    print()
    if vex.release_date:
        console.print(f'Public on : [cyan]{vex.release_date}[/cyan]', highlight=False)
    if vex.global_impact:
        console.print(f'Impact    : [{SEVERITY_COLOR[vex.global_impact]}]{vex.global_impact}[/{SEVERITY_COLOR[vex.global_impact]}]')
    if vex.global_cvss:
        console.print(f"CVSS Score: [cyan]{vex.global_cvss.baseScore}[/cyan]", highlight=False)
    print()

    # any known exploits?
    if len(vex.exploits) > 0:
        console.print(f"[red]Known to be exploited![/red]")
        for ex in vex.exploits:
            if ex['source']:
                print(f"  {ex['date']} - {ex['source']} ({ex['url']})")
            else:
                print(f"  {ex['date']} - {ex['details']}")
        print()

    # print the notes from the VEX document
    if 'summary' in vex.notes:
        for (title, text) in vex.notes['summary'].items():
            console.print(f"[green]{title}[/green]\n{text}\n", highlight=False)
    if 'description' in vex.notes:
        for (title, text) in vex.notes['description'].items():
            console.print(f"[green]{title}[/green]\n{text}\n", highlight=False)
    if 'general' in vex.notes:
        for (title, text) in vex.notes['general'].items():
            console.print(f"[green]{title}[/green]\n{text}\n", highlight=False)
    if 'legal_disclaimer' in vex.notes:
        for (title, text) in vex.notes['legal_disclaimer'].items():
            console.print(f"[green]{title}[/green]\n{text}\n", highlight=False)

    if vex.statement:
        console.print('[green]Statement[/green]')
        print(f'  {vex.statement}')
        print()

    mitigation = None
    if packages.mitigation:
        console.print('[green]Mitigation[/green]')
        if len(packages.mitigation) > 1:
            console.print('[bold red]**WARNING**: MORE THAN ONE MITIGATION DISCOVERED![/bold red]')
        for x in packages.mitigation:
            # Red Hat at least uses Markdown here, so let's render it
            console.print(Markdown(x.details))
        print()

    refs = []
    if vex.bz_id:
        refs.append(f'  Bugzilla: {vex.bz_id}')
    if vex.cwe_id:
        refs.append(f'  [blue]{vex.cwe_id}[/blue] : {vex.cwe_name}')
    if refs:
        console.print('[green]Additional Information[/green]')
        for r in refs:
            console.print(r, highlight=False)
    print()

    if vex.references:
        console.print('[green]External References[/green]')
        for url in vex.references:
            print(f'  {url}')
        print()

    publisher = 'Unknown'
    # the vendor for Red Hat VEX is Red Hat Product Security which isn't right,
    # so we'll override until there's a fix
    if vex.publisher:
        if vex.publisher == 'Red Hat Product Security':
            publisher = 'Red Hat'
        else:
            publisher = vex.publisher

    if packages.fixes:
        console.print(f'[green]{publisher} affected packages and issued errata[/green]')
        for x in packages.fixes:
            console.print(f"  [blue]{x.id}[/blue] -- {x.product}", highlight=False)
            if args.show_components:
                for c in list(set(x.components)):
                    print(f'             {c}')
        print()

    if packages.not_affected:
        console.print('[green]Packages that are not affected[/green]')
        for x in packages.not_affected:
            print(f"  {x.product} ({', '.join(x.components)})")
        print()

    if packages.wontfix:
        console.print('[green]Affected packages that will not be fixed[/green]')
        for x in packages.wontfix:
            console.print(f"  {x.product} ({x.component}): [red]{x.reason}[/red]")
        print()

    if packages.affected:
        console.print('[green]Affected packages without fixes[/green]')
        for x in packages.affected:
            console.print(f"  {x.product} ({', '.join(x.components)})")
        print()

    if vex.global_cvss:
        # which version of CVSS are we using?
        cvssVersion = ''
        if vex.global_cvss.version is not None:
            # this is our default
            cvssVersion = vex.global_cvss.version

        if cvssVersion == '':
            if nvd.cvss31.version is not None:
                cvssVersion = '3.1'

        if cvssVersion == '3.1':
            nvd = nvd.cvss31

        if cvssVersion == '3.0':
            nvd = nvd.cvss30

        if cvssVersion == '2.0':
            nvd = nvd.cvss20

        console.print(f'[green]CVSS {cvssVersion} Vector[/green]')
        plen = 4
        if len(publisher) > 4:
            plen = len(publisher)
        print(f"  {publisher:{plen}}: {vex.global_cvss.vectorString}")
        if not args.no_nvd:
            print(f'  {"NVD":{plen}}: {nvd.vectorString}')
        print()

        console.print(f'[green]CVSS {cvssVersion} Score Breakdown[/green]')
        print(f"{' ':26} {publisher:<10} NVD")
        if cvssVersion == '3.0' or cvssVersion == '3.1':
            # not all VEX will break down the metrics
            if vex.global_cvss.attackVector:
                print(f"  {f'CVSS {cvssVersion} Base Score':24} {vex.global_cvss.baseScore:<10} {nvd.baseScore}")
                print(f"  {'Attack Vector':24} {vex.global_cvss.attackVector:10} {nvd.attackVector}")
                print(f"  {'Attack Complexity':24} {vex.global_cvss.attackComplexity:10} {nvd.attackComplexity}")
                print(f"  {'Privileges Required':24} {vex.global_cvss.privilegesRequired:10} {nvd.privilegesRequired}")
                print(f"  {'User Interaction':24} {vex.global_cvss.userInteraction:10} {nvd.userInteraction}")
                print(f"  {'Scope':24} {vex.global_cvss.scope:10} {nvd.scope}")
        elif cvssVersion == '2.0':
            if vex.global_cvss.accessVector:
                # not all VEX will break down the metrics
                print(f"  {'CVSS v2 Base Score':24} {vex.global_cvss.baseScore:<10} {nvd.baseScore}")
                print(f"  {'Access Vector':24} {vex.global_cvss.accessVector:10} {nvd.accessVector}")
                print(f"  {'Access Complexity':24} {vex.global_cvss.accessComplexity:10} {nvd.accessComplexity}")
                print(f"  {'Authentication':24} {vex.global_cvss.authentication:10} {nvd.authentication}")
        if vex.global_cvss.confidentialityImpact:
            print(f"  {'Confidentiality Impact':24} {vex.global_cvss.confidentialityImpact:10} {nvd.confidentialityImpact}")
            print(f"  {'Integrity Impact':24} {vex.global_cvss.integrityImpact:10} {nvd.integrityImpact}")
            print(f"  {'Availability Impact':24} {vex.global_cvss.availabilityImpact:10} {nvd.availabilityImpact}")
        print()

    if vex.acks:
        console.print('[green]Acknowledgements[/green]')
        print(f'{vex.acks}')
        print()

    if vex.distribution:
        print(vex.distribution)

if __name__ == '__main__':
    main()
