#!/usr/bin/env python3

# Read and process a VEX document
# i.e. https://access.redhat.com/security/data/csaf/beta/vex/2024/cve-2024-21626.json

import argparse
from datetime import timezone, datetime
import os
import json

severity = {'Critical': 4, 'Important': 3, 'Moderate': 2, 'Low': 1}

def get_rating(score):
    # map the score to a severity category
    if 0.1 <= score <= 3.9:
        return 'Low'
    elif 4.0 <= score <= 6.9:
        return 'Medium'
    elif 7.0 <= score <= 8.9:
        return 'High'
    elif score >= 9.0:
        return 'Critical'
    else:
        return 'None'


def filter_products(products):
    # strip out all arches from product listings
    arches    = ['ppc64le', 'ppc64', 'ppc', 'i686', 's390x', 'x86_64', 'aarch64', 'noarch']
    forbidden = ['debuginfo', 'kernel-headers']
    filtered  = []

    for p in products:
        if '.src' in p:
            filtered.append(p.replace('.src', ''))

    if len(filtered) == 0:
        # there was no srpm
        for p in products:
            if 'x86_64' in p:
                skip = False
                # filter out any forbidden package names like debuginfo which will pollute our output
                for f in forbidden:
                    if f in p:
                        skip = True
                if not skip:
                    filtered.append(p.replace('.x86_64', ''))
    return filtered


def product_lookup(product, pmap):
    # lookup the product name by identifier
    for x in pmap:
        if product in x.keys():
            return x[product]


def main():
    parser = argparse.ArgumentParser(description='VEX Parser')
    parser.add_argument('--vex', dest='vex', metavar="FILE", help='VEX file to process', required=True)
    parser.add_argument('--show-components', dest='show_components', action='store_true', default=False, help='Show components in output')

    args = parser.parse_args()

    if not os.path.exists(args.vex):
        print(f'Missing VEX file: {args.vex}.')
        exit(1)

    with open(args.vex) as fp:
        vex = json.load(fp)

    # keys": 'document', 'product_tree', 'vulnerabilities'
    #print(vex['document'])
    global_impact = vex['document']['aggregate_severity']['text'].capitalize()
    distribution  = vex['document']['distribution']['text']


    # build the product tree which has a weird amount of depth but ok...
    pmap = []
    for p in vex['product_tree']['branches']:
        for b in p['branches']:
            if 'branches' in b.keys():
                for c in b['branches']:
                    if 'category' in c.keys():
                        if c['category'] == 'product_name':
                            name = c['name']
                            id = c['product']['product_id']
                            pmap.append({id: name})

    for k in vex['vulnerabilities']:
        title  = k['title']
        cve    = k['cve']
        cwe_id = None
        if 'cwe' in k:
            cwe_id = k['cwe']['id']
            cwe_name = k['cwe']['name']
        discovery_date = k['discovery_date']
        rd = datetime.fromisoformat(k['release_date'])
        release_date = rd.astimezone().strftime('%Y-%m-%d') # TODO: force this to be Eastern

        # Acknowledgements
        acks = None
        if 'acknowledgements' in k:
            for x in k['acknowledgments']:
                # we should always have names, but may not always have an organization
                # (if the credit is to an org, the org is the name)
                if 'organization' not in x:
                    x['organization'] = ''
                ack_list = {'names': x['names'], 'org': x['organization']}
                if len(ack_list['names']) > 1:
                    names = " and ".join(ack_list['names'])
                else:
                    names = ack_list['names'][0]

                if ack_list['org'] == '':
                    acks = names
                else:
                    acks = f"{names} ({ack_list['org']})"

        # Bugzilla / bugtracking
        for x in k['ids']:
            if x['system_name'] == 'Red Hat Bugzilla ID':
              bz_id = x['text']
              bz_url = f'https://bugzilla.redhat.com/show_bug.cgi?id={bz_id}'

        # Notes including descriptions, summaries, statements
        description = None
        summary     = None
        statement   = None

        for x in k['notes']:
            if x['category'] == 'description':
                description = x['text']
            if x['category'] == 'summary':
                summary = x['text']
            if x['category'] == 'other' and x['title'] == 'Statement':
                statement = x['text']

        # external references
        references = []
        for x in k['references']:
            if x['category'] == 'self':
                continue
            if x['category'] == 'external':
                references.append(x['url'])

        # product status
        not_affected = []
        affected     = []
        if 'product_status' in k:
            for x in k['product_status']:
                if x == 'known_affected':
                    for y in filter_products(k['product_status']['known_affected']):
                        affected.append(y)
                if x == 'known_not_affected':
                    for y in filter_products(k['product_status']['known_not_affected']):
                        not_affected.append(y)

        # errata
        fixes       = []
        workarounds = []
        wontfix     = []
        if 'remediations' in k:
            for x in k['remediations']:
                if x['category'] == 'vendor_fix':
                    rhsa = None
                    url = x['url']
                    if 'RHSA' in url:
                        rhsa = url.split('/')[-1]
                    f_pkgs = filter_products(x['product_ids'])
                    fixes.append({'rhsa': rhsa, 'url': url, 'packages': f_pkgs})

                if x['category'] == 'workaround':
                    wa_details = x['details']
                    # seems stupid to have a package list for workarounds
                    # but... just in case
                    w_pkgs = filter_products(x['product_ids'])
                    workarounds.append({'details': wa_details, 'packages': w_pkgs})

                if x['category'] == 'no_fix_planned':
                    nf_details = x['details']
                    for p in x['product_ids']:
                        wontfix.append({'product': p, 'reason': nf_details})

        # TODO: are there any cases where there may be more than one workaround?
        if len(workarounds) > 1:
            print('**WARNING**: MORE THAN ONE MITIGATION DISCOVERED!')
            # NOTE: because this would be interesting to catch, let's make it a hard fail for now
            exit(1)

        mitigation = None
        for w in workarounds:
            mitigation = w['details']

        cvss_v3 = []
        cvss_v2 = []
        if 'scores' in k:
            for x in k['scores']:
                if 'products' in x:
                    filtered_products = filter_products(x['products'])
                if 'cvss_v3' in x:
                    cvss_v3.append({'scores': x['cvss_v3'], 'products': filtered_products})
                elif 'cvss_v2' in x:
                    cvss_v2.append({'scores': x['cvss_v2'], 'products': filtered_products})

        global_cvss = None
        cvss_type = None
        if cvss_v3:
            cvss_type = 'v3'
            if len(cvss_v3) == 1:
                global_cvss = cvss_v3[0]['scores']
            #else:
            # TODO: something fancy to assign alternate CVSS to other packages
            #print(cvss_v3)

        if cvss_v2:
            cvss_type = 'v2'
            if len(cvss_v2) == 1:
                if not global_cvss:
                    global_cvss = cvss_v2[0]['scores']
            #else:
            # TODO: something fancy like above
            #print(cvss_v2)

        impacts = {'Critical': [], 'Important': [], 'Moderate': [], 'Low': []}
        if 'threats' in k:
            for x in k['threats']:
                if x['category'] == 'impact':
                    # need to map impacts to products
                    for y in filter_products(x['product_ids']):
                        impacts[x['details']].append(y)
                    #impacts.append({x['details']: filter_products(x['product_ids'])})

        # we can drop those that match the "global" impact by setting the list to empty
        impacts[global_impact] = []


        print(cve)
        print(f'Public on {release_date}')
        #TODO: add updated date
        print(f'{global_impact} Impact')
        if global_cvss:
            print(f"{global_cvss['baseScore']} CVSS Score")
        print()
        print('Description:')
        print(f'  {description}')
        print()
        if statement:
            print('Statement:')
            print(f'  {statement}')
            print()

        if mitigation:
            print('Mitigation:')
            print(f'  {mitigation}')
            print()

        print('Additional Information:')
        print(f'  Bugzilla {bz_id}: {summary}')
        if cwe_id:
            print(f'  {cwe_id}: {cwe_name}')
        print()
        print('External References:')
        for url in references:
            print(f'  {url}')
        print()

        print('Affected Packages and Issued Red Hat Security Errata:')
        for x in fixes:
            # TODO: this is missing the release date for the RHSA, see https://issues.redhat.com/browse/SECDATA-645
            # TODO: this is also missing any changed CVSS scores
            rhsa_id  = x['rhsa']
            rhsa_url = x['url']
            component_versions = []
            component_names    = []
            for y in x['packages']:
                # look for any different severities from the global
                severity = ''
                for i in impacts:
                    if y in impacts[i]:
                        severity = f' [Severity: {i}]'
                (product, comp, version) = y.split(':')
                # only care about components
                component_versions.append(':'.join([comp, version]))
                # NOTE: the epoch is appended to the component name (i.e. runc with an epoch of 0 is runc-0, with
                # an epoch of 4 it's runc-4 ... this is meaningless information for consumers frankly and we
                # shouldn't do it, but there it is...  for presentation, let's weed it out
                c_name = '-'.join(comp.split('-')[:-1])
                if c_name not in component_names:
                    # get list of components and de-duplicate
                    component_names.append(c_name)
            product_name = product_lookup(product, pmap)

            if args.show_components:
                print(f"  {rhsa_id} -- {product_name}{severity}")
                for c in list(set(component_versions)):
                    print(f'             {c}')
            else:
                # TODO: if we look at CVE-2024-21626 as one example, we get a list of components that technically are
                # not affected, how do we refine this down to the one component that is? (i.e. show 'runc' and not
                # 'podman' and 'skopeo', etc)
                print(f"  {rhsa_id} -- {product_name}{severity} -- {', '.join(component_names)}")

# TODO: need to filter these products like we do for fixes; can test with cve-2022-1012.json
        if not_affected:
            for x in not_affected:
                # omg these strings are ridiculous
                t = x.split(':')
                p = t[0]  # product
                c = ':'.join(t[1:])  # component
                product_name = product_lookup(p, pmap)
                print(f'  {product_name} -- {c} -- Not Affected')

        if wontfix:
            for x in wontfix:
                # omg these strings are ridiculous
                t = x['product'].split(':')
                p = t[0]  # product
                c = ':'.join(t[1:])  # component
                product_name = product_lookup(p, pmap)
                print(f"  {product_name} -- {c} -- {x['reason']}")
                if x['product'] in affected:
                    affected.remove(x['product'])

        if affected:
            for x in affected:
                # omg these strings are ridiculous
                t = x['product'].split(':')
                p = t[0]  # product
                c = ':'.join(t[1:])  # component
                product_name = product_lookup(p, pmap)
                print(f'  {product_name} -- {c} -- Affected')

        print()
        # TODO: see https://issues.redhat.com/browse/SECDATA-647 for CVE pages that exist but for which VEX documents
        # do not exist (also see https://issues.redhat.com/browse/SECDATA-525 where the work is being done)

        if global_cvss:
            print(f'CVSS {cvss_type} Vector')
            print(f"Red Hat: {global_cvss['vectorString']}")
            print('NVD:      **NOT YET**')
            print()
            print(f'CVSS {cvss_type} Score Breakdown')
            # TODO: string padding
            print('                        Red Hat    NVD')
            print(f"CVSS v3 Base Score      {global_cvss['baseScore']}        0.0")
            print(f"Attack Vector           {global_cvss['attackVector'].capitalize()}")
            print(f"Attack Complexity       {global_cvss['attackComplexity'].capitalize()}")
            print(f"Privileges Required     {global_cvss['privilegesRequired'].capitalize()}")
            print(f"User Interaction        {global_cvss['userInteraction'].capitalize()}")
            print(f"Scope                   {global_cvss['scope'].capitalize()}")
            print(f"Confidentiality Impact  {global_cvss['confidentialityImpact'].capitalize()}")
            print(f"Integrity Impact        {global_cvss['integrityImpact'].capitalize()}")
            print(f"Availability Impact     {global_cvss['availabilityImpact'].capitalize()}")
            print()

        if acks:
            print('Acknowledgements:')
            print(f'  Red Hat would like to thank {acks} for reporting this issue.')

        print(distribution)

"""
        print(title)
        #print(acks)

        print(cwe_id)
        print(cwe_name)
        print(bz_url)
        print(f'DESCRIPTION: {description}')
        print(f'SUMMARY: {summary}')
        print(f'STATEMENT: {statement}')
        print(discovery_date) # date reported to us
        print(release_date)   # date we made this public
        print('FIXES:')
        for x in fixes:
            print(x)
        print('WONTFIX:')
        for x in wontfix:
            print(x)
        print('WORKAROUNDS:')
        for x in workarounds:
            print(x)
#        print(fixes)
        print(global_cvss['vectorString'])
        print(global_impact)
        exit
        #print(vex['vulnerabilities'].keys())
"""

if __name__ == '__main__':
    main()
