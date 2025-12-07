# Copyright (c) 2024 Vincent Danen
# License: GPLv3+

from datetime import datetime
import pytz
from .constants import (
    filter_components,
    VENDOR_ADVISORY,
    ARCHES,
    TZ
)


def product_lookup(product, pmap):
    # lookup product information by identifier, return a tuple of (name, cpe, purl)
    name = None
    cpe  = None
    purl = None

    for x in pmap:
        if product in x.keys():
            if 'name' in x[product]:
                name = x[product]['name']
            if 'cpe' in x[product]:
                cpe = x[product]['cpe']
            if 'purl' in x[product]:
                purl = x[product]['purl']

            return (name, cpe, purl)

    # our pmap has no products so return an empty tuple
    return (name, cpe, purl)


def dedupe(component_list):
    return list(dict.fromkeys(component_list))


def strip_arch(oldComponent):
    """
    Strip any reference to an architecture from the component name; this will help to reduce duplicates, i.e.
    foo-1.2-1.x86_64 and foo-1.2-1.ppc64 should be one entry, not two, so iterate through ARCHES to see if they
    are present and if so, remove them and return a new component name

    :param oldComponent: the component string to remove architecture references from
    :return: string of the component without architecture
    """
    newComponent = None

    for a in ARCHES:
        if a in oldComponent:
            newComponent = oldComponent.replace(f'.{a}', '')

    if not newComponent:
        newComponent = oldComponent

    return newComponent


def product_and_components(y):
    components = []
    t = y.split(':')
    product = t[0]
    components.append(':'.join(t[1:]))

    return (product, components)


class Fix(object):
    """
    class to handle vendor fixes
    """

    def __init__(self, x, pmap):
            self.id         = None
            self.url        = ''
            self.date       = None
            self.components = []

            if 'url' in x:
                self.url = x['url']

            if 'date' in x:
                if x['date'].endswith('Z'):
                    pd       = datetime.fromisoformat(x['date'][:-1])
                    pd       = pd.replace(tzinfo=pytz.timezone('UTC'))
                else:
                    pd        = datetime.fromisoformat(x['date'])
                self.date = pd.astimezone(pytz.timezone(TZ)).strftime('%B %d, %Y')

            for v in VENDOR_ADVISORY:
                if v in self.url:
                    # most advisories have the advisory name at the end of the URL
                    self.id = self.url.split('/')[-1]
                    self.vendor = VENDOR_ADVISORY[v]
                    # ... but some don't
                    if self.vendor == 'Gentoo':
                        self.id = f'{v}-{self.id}'

            for y in filter_components(x['product_ids']):
                if len(y.split(':')) == 1:
                    # we may not have a component or version, just a product name
                    self.pid = y
                    (self.product, self.cpe, self.purl) = product_lookup(y, pmap)
                elif len(y.split(':')) == 2:
                    # bloody containers without versions
                    self.pid = y
                    (self.product, self.cpe, self.purl) = product_lookup(y, pmap)
                else:
                    # modular components can have 7 colons
                    (product, component, version) = y.split(':', maxsplit=2)
                    self.pid = product
                    self.components.append(':'.join([component, version]))
                    (self.product, self.cpe, self.purl) = product_lookup(product, pmap)

            self.components = dedupe(self.components)


class WontFix(object):
    """
    class to handle affects that the vendor will not fix.  These come as one (or multiple?) list of product ids
    with a reason
    """

    def __init__(self, y, x, pmap):
        (product, self.component) = y.split(':', maxsplit=1)
        self.raw                  = y
        self.reason               = x['details']
        self.pid                  = product
        (self.product, self.cpe, self.purl) = product_lookup(product, pmap)


class NotAffected(object):
    """
    class to handle products listed as not affected
    """

    def __init__(self, y, pmap):
        (product, components) = product_and_components(y)
        self.raw              = y
        self.components       = components
        self.pid              = product
        (self.product, self.cpe, self.purl) = product_lookup(product, pmap)


class Affected(object):
    """
    class to handle products listed as affected with no resolution
    """

    def __init__(self, y, pmap):
        (product, components) = product_and_components(y)
        self.raw              = y
        self.components       = components
        self.pid              = product
        (self.product, self.cpe, self.purl) = product_lookup(product, pmap)


class Mitigation(object):
    """
    class to handle products listed with mitigations

    There should only be one mitigation and not multiple; there may be one mitigiation with
    a large component list, however -- we probably don't need the components but will keep them
    just in case
    """

    def __init__(self, x):
        self.details  = x['details']
        self.packages = filter_components(x['product_ids'])


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
            if not 'branches' in p:
                # there are no product branches, meaning no products
                continue
            # TODO there seems to be a bug in the VEX output respective to branch nesting, it's very convoluted =(
            for b in p['branches']:
                if 'branches' in b.keys():
                    for c in b['branches']:
                        if 'category' in c.keys():
                            if c['category'] == 'product_name':
                                name = c['name']
                                # seems we can also nest branches here?
                                if 'branches' in c.keys():
                                    for d in c['branches']:
                                        cpe  = None
                                        purl = None
                                        id  = d['product']['product_id']
                                        if 'product_identification_helper' in d['product']:
                                            if 'cpe' in d['product']['product_identification_helper']:
                                                cpe = d['product']['product_identification_helper']['cpe']
                                            if 'purl' in d['product']['product_identification_helper']:
                                                purl = d['product']['product_identification_helper']['purl']
                                else:
                                    cpe  = None
                                    purl = None
                                    id  = c['product']['product_id']
                                    if 'product_identification_helper' in c['product']:
                                        if 'cpe' in c['product']['product_identification_helper']:
                                            cpe = c['product']['product_identification_helper']['cpe']
                                        if 'purl' in c['product']['product_identification_helper']:
                                            purl = c['product']['product_identification_helper']['purl']
                                self.pmap.append({id: {'name': name, 'cpe': cpe, 'purl': purl}})


    def parse_packages(self):
        # errata
        self.fixes        = []
        self.mitigation   = []
        self.wontfix      = []
        self.affected     = []
        self.not_affected = []

        for k in self.raw['vulnerabilities']:
            if 'remediations' in k:
                for x in k['remediations']:
                    if x['category'] == 'vendor_fix':
                        # TODO: the assumption here is that there is one product, and potentially many components
                        # which doesn't seem to be the case, see https://www.sick.com/.well-known/csaf/white/2024/sca-2024-0001.json
                        # which has two vendor_fix statements, but the second has more than one product_ids; this will
                        # require some rejiggering to make it show products and not just None
                        self.fixes.append(Fix(x, self.pmap))
                        #print(f'Appended: {x}')

                    if x['category'] == 'workaround':
                        self.mitigation.append(Mitigation(x))

                    if x['category'] == 'no_fix_planned':
                        # don't filter anything on components with no fix planned as there aren't
                        # any real components (so no .src or .[arch] packages to filter)
                        for y in (x['product_ids']):
                            self.wontfix.append(WontFix(y, x, self.pmap))

            if 'product_status' in k:
                for x in k['product_status']:
                    if x == 'known_affected':
                        for y in filter_components(k['product_status']['known_affected']):
                            self.affected.append(Affected(y, self.pmap))
                    if x == 'known_not_affected':
                        for y in filter_components(k['product_status']['known_not_affected']):
                            # this is for those "does not affect us CVEs"; at least Red Hat does this so if we see this
                            # we don't build a not-affects list, we just leave it empty
                            if y == 'red_hat_products':
                                continue
                            # check to make sure we're not adding a dupe
                            addMe = True
                            for na in self.not_affected:
                                if strip_arch(y) in na.raw:
                                    addMe = False
                            if addMe:
                                self.not_affected.append(NotAffected(strip_arch(y), self.pmap))
