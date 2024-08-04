# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from .constants import (
    filter_products,
    VENDOR_ADVISORY,
)

def product_lookup(product, pmap):
    # lookup the product name by identifier
    for x in pmap:
        if product in x.keys():
            return x[product]

class Fix(object):
    """
    class to handle vendor fixes
    """

    def __init__(self, x, pmap):
            self.id         = None
            self.url        = x['url']
            self.components = []

            for v in VENDOR_ADVISORY:
                if v in self.url:
                    # most advisories have the advisory name at the end of the URL
                    self.id = self.url.split('/')[-1]
                    self.vendor = VENDOR_ADVISORY[v]
                    # ... but some don't
                    if self.vendor == 'Gentoo':
                        self.id = f'{v}-{self.id}'

            for y in filter_products(x['product_ids']):
                (product, component, version) = y.split(':')
                self.components.append(':'.join([component, version]))
                self.product = product_lookup(product, pmap)


class WontFix(object):
    """
    class to handle affects that the vendor will not fix.  These come as one (or multiple?) list of product ids
    with a reason
    """

    def __init__(self, x, y, pmap):
            print('hit')
            self.reason     = x['details']
            (product, self.component) = y.split(':')
            self.product = product_lookup(product, pmap)


class VexPackages(object):
    """
    class to handle packages
    """

    def __init__(self, vexdata):
        self.raw = vexdata
        self.build_product_tree()
        self.parse_packages()

    def build_product_tree(self):
        """
        Parse included packages
        :return:
        """

        self.pmap = []
        for p in self.raw['product_tree']['branches']:
            # TODO there seems to be a bug in the VEX output respective to branch nesting, it's very convoluted =(
            for b in p['branches']:
                if 'branches' in b.keys():
                    for c in b['branches']:
                        if 'category' in c.keys():
                            if c['category'] == 'product_name':
                                name = c['name']
                                id   = c['product']['product_id']
                                self.pmap.append({id: name})


    def parse_packages(self):
        # errata
        self.fixes       = []
        self.workarounds = []
        self.wontfix     = []
        for k in self.raw['vulnerabilities']:
            if 'remediations' in k:
                for x in k['remediations']:
                    if x['category'] == 'vendor_fix':
                        self.fixes.append(Fix(x, self.pmap))

                    if x['category'] == 'workaround':
                        wa_details = x['details']
                        # seems stupid to have a package list for workarounds
                        # but... just in case
                        w_pkgs = filter_products(x['product_ids'])
                        self.workarounds.append({'details': wa_details, 'packages': w_pkgs})

                    if x['category'] == 'no_fix_planned':
                        for y in filter_products(x['product_ids']):
                            self.wontfix.append(WontFix(x, y, self.pmap))
